package media

import (
	"context"
	"encoding/json"
	"errors"
	storage "github.com/StuHelper/stuhelper-storage"
	"mime"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

type Service struct {
	repo    Repository
	auth    Authorizer
	store   Store
	cfg     Config
	now     func() time.Time
	slots   chan struct{}
	staging *uploadStaging
	ctx     context.Context
	cancel  context.CancelFunc
	mu      sync.Mutex
	closed  bool
	active  sync.WaitGroup
}

func New(r Repository, a Authorizer, store Store, c Config) (*Service, error) {
	if r == nil || a == nil || store == nil || !c.Actor.Valid() || len(c.Profiles) == 0 || len(c.Profiles) > 64 || c.UploadTTL < time.Minute || c.UploadTTL > 24*time.Hour || c.UnreferencedTTL < c.UploadTTL || c.UnreferencedTTL > 24*time.Hour || c.OperationTimeout < time.Second || c.OperationTimeout > 5*time.Minute || c.ParallelTransfers < 1 || c.ParallelTransfers > 16 || c.MaxOpenUploads < 1 || c.MaxOpenUploads > 100 || c.MaxFilesPerOwner < 1 || c.MaxFilesPerOwner > 10000 || c.MaxVersions < 1 || c.MaxVersions > 100 || c.MaxReferences < 1 || c.MaxReferences > 100 || c.MaxAttempts < 1 || c.MaxAttempts > 100 {
		return nil, ErrInput
	}
	if c.PendingApprovalTTL == 0 {
		c.PendingApprovalTTL = c.UnreferencedTTL
	}
	if c.PendingApprovalTTL < c.UnreferencedTTL || c.PendingApprovalTTL > 24*time.Hour {
		return nil, ErrInput
	}
	if c.MaxArchiveFiles == 0 {
		c.MaxArchiveFiles = 100
	}
	if c.MaxArchiveBytes == 0 {
		c.MaxArchiveBytes = 1 << 30
	}
	if c.MaxArchiveFiles < 1 || c.MaxArchiveFiles > 100 || c.MaxArchiveBytes < 1 || c.MaxArchiveBytes > 1<<30 {
		return nil, ErrInput
	}
	if c.HistoryRetention == 0 {
		c.HistoryRetention = 24 * time.Hour
	}
	if c.HistoryRetention < time.Minute || c.HistoryRetention > 365*24*time.Hour {
		return nil, ErrInput
	}
	profiles := make(map[string]Profile, len(c.Profiles))
	var maxProfileSize int64
	for name, p := range c.Profiles {
		if (p.SchoolID != "" && !idOK(p.SchoolID)) || !idOK(name) || !idOK(p.Module) || !p.Quarantine.Valid() || p.Quarantine.Public || !p.Published.Valid() || p.Published.Scope != p.Quarantine.Scope || (!p.Published.Public && p.Published != p.Quarantine) || p.MaxSize < 1 || p.MaxSize > 1<<30 || len(p.AllowedTypes) == 0 || len(p.AllowedTypes) > 32 {
			return nil, ErrInput
		}
		for _, v := range p.AllowedTypes {
			typ, params, e := mime.ParseMediaType(v)
			if e != nil || typ != v || len(params) != 0 || !supportedType(v) {
				return nil, ErrInput
			}
		}
		p.AllowedTypes = slices.Clone(p.AllowedTypes)
		profiles[name] = p
		maxProfileSize = max(maxProfileSize, p.MaxSize)
	}
	if c.MaxStagingBytes == 0 {
		c.MaxStagingBytes = min(max(4*maxProfileSize, 64<<20), 1<<30)
	}
	if c.MaxStagingBytes < maxProfileSize || c.MaxStagingBytes > 16<<30 {
		return nil, ErrInput
	}
	staging, err := openUploadStaging(c.StagingDirectory, c.MaxStagingBytes)
	if err != nil {
		return nil, err
	}
	c.Profiles = profiles
	now := c.Clock
	if now == nil {
		now = time.Now
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Service{repo: r, auth: a, store: store, cfg: c, now: now, slots: make(chan struct{}, c.ParallelTransfers), staging: staging, ctx: ctx, cancel: cancel}, nil
}
func (s *Service) Close(ctx context.Context) error {
	s.mu.Lock()
	s.closed = true
	s.cancel()
	s.mu.Unlock()
	done := make(chan struct{})
	go func() { s.active.Wait(); close(done) }()
	select {
	case <-done:
		return s.staging.close()
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (s *Service) operation(ctx context.Context) (context.Context, func(), error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, nil, ErrUnavailable
	}
	s.active.Add(1)
	s.mu.Unlock()
	work, cancel := context.WithTimeout(ctx, s.cfg.OperationTimeout)
	stop := context.AfterFunc(s.ctx, cancel)
	return work, func() { stop(); cancel(); s.active.Done() }, nil
}

// OperationTimeout is the maximum duration of one media request.
func (s *Service) OperationTimeout() time.Duration { return s.cfg.OperationTimeout }
func (s *Service) begin(ctx context.Context) (context.Context, func(), error) {
	work, done, err := s.operation(ctx)
	if err != nil {
		return nil, nil, err
	}
	select {
	case s.slots <- struct{}{}:
		return work, func() { <-s.slots; done() }, nil
	default:
		done()
		return nil, nil, withLimit(ErrTransferBusy, int64(s.cfg.ParallelTransfers))
	}
}
func (s *Service) authorize(ctx context.Context, p Principal, action string, a Access) error {
	if s.ctx.Err() != nil {
		return ErrUnavailable
	}
	if !p.Valid() {
		return ErrDenied
	}
	if e := s.auth.Authorize(ctx, p, action, a); e != nil {
		if errors.Is(e, ErrDenied) || errors.Is(e, storage.ErrDenied) {
			return ErrDenied
		}
		return ErrUnavailable
	}
	return nil
}
func versionProtection(v Version) Protection {
	if v.Approved {
		return v.Profile.Published
	}
	return v.Profile.Quarantine
}
func access(f File, v Version, r *Reference) Access {
	return Access{FileID: f.ID, VersionID: v.ID, Purpose: f.Purpose, Owner: f.Owner, Protection: versionProtection(v), Reference: r}
}
func (s *Service) authorizeFile(ctx context.Context, p Principal, action string, f File, vs []Version) error {
	var seen []Protection
	for _, v := range vs {
		prot := versionProtection(v)
		if slices.Contains(seen, prot) {
			continue
		}
		seen = append(seen, prot)
		if e := s.authorize(ctx, p, action, access(f, v, nil)); e != nil {
			return e
		}
	}
	return nil
}
func (s *Service) load(tx Transaction, id string) (File, Version, error) {
	if !idOK(id) {
		return File{}, Version{}, ErrInput
	}
	v, e := tx.Version(id)
	if e != nil {
		return File{}, v, e
	}
	// File -> version locks serialize deletion with version creation and changes.
	if e = tx.Lock("file:" + v.FileID); e != nil {
		return File{}, v, e
	}
	f, e := tx.File(v.FileID)
	if e != nil {
		return f, v, e
	}
	v, e = tx.Version(id)
	return f, v, e
}
func validKey(k string) bool {
	return len(k) > 0 && len(k) <= 128 && strings.IndexFunc(k, func(r rune) bool { return r < 32 || r > 126 }) < 0
}
func (s *Service) mutation(ctx context.Context, p Principal, action, id, key string, request any, guard func(Transaction) error, apply func(Transaction) (any, error), out any) error {
	if !validKey(key) || !p.Valid() {
		return ErrInput
	}
	op := hash([]string{p.Issuer, p.Subject, action, id, key})
	fingerprint := hash(request)
	return s.repo.Transaction(ctx, func(tx Transaction) error {
		if e := tx.Lock("operation:" + op); e != nil {
			return e
		}
		if e := guard(tx); e != nil {
			return e
		}
		old, e := tx.Replay(op, s.now())
		if e == nil {
			if old.Digest != fingerprint {
				return ErrConflict
			}
			if json.Unmarshal(old.Result, out) != nil {
				return ErrUnavailable
			}
			return nil
		}
		if !errors.Is(e, ErrNotFound) {
			return e
		}
		value, e := apply(tx)
		if e != nil {
			return e
		}
		b, e := json.Marshal(value)
		if e != nil {
			return ErrUnavailable
		}
		if e = tx.SaveReplay(Replay{Key: op, Digest: fingerprint, Result: b, CreatedAt: s.now().UTC()}); e != nil {
			return e
		}
		return json.Unmarshal(b, out)
	})
}
func (s *Service) emit(ctx context.Context, tx Transaction, p Principal, kind, id string, revision int64, school string, ref *Reference) error {
	var data EventData
	if ref != nil {
		data = EventData{ReferenceID: ref.ID, FileID: ref.FileID, Module: ref.Module, ResourceID: ref.ResourceID}
	}
	trace, _ := ctx.Value(traceParentKey{}).(string)
	return tx.Event(Event{Data: data, SchoolID: school, TraceParent: trace, ID: newID(), Type: kind + ".v1", Subject: id, Revision: revision, Time: s.now(), Actor: p})
}
func (s *Service) schedule(tx Transaction, id string, reset bool) error {
	j, e := tx.Job(id)
	if e != nil && !errors.Is(e, ErrNotFound) {
		return e
	}
	if j.State == "running" {
		return nil
	}
	if !reset && (j.State == "blocked" || (j.State == "pending" && j.Attempts > 0)) {
		return nil
	}
	j.VersionID = id
	j.State = "pending"
	j.AvailableAt = s.now()
	if reset {
		j.Attempts = 0
		j.ErrorCode = ""
	}
	return tx.SaveJob(j)
}
func (s *Service) save(ctx context.Context, tx Transaction, p Principal, v Version, kind string, ref *Reference) error {
	v.Revision++
	if e := tx.SaveVersion(v); e != nil {
		return e
	}
	if e := s.schedule(tx, v.ID, true); e != nil {
		return e
	}
	return s.emit(ctx, tx, p, kind, v.ID, v.Revision, v.Profile.SchoolID, ref)
}
func validFilename(v string) bool {
	if !utf8.ValidString(v) || len(v) == 0 || len(v) > 240 || strings.HasSuffix(v, ".") || strings.HasSuffix(v, " ") || strings.ContainsAny(v, `<>:"/\|?*`) || strings.IndexFunc(v, unicode.IsControl) >= 0 {
		return false
	}
	stem, _, _ := strings.Cut(v, ".")
	stem = strings.ToUpper(strings.TrimRight(stem, " "))
	switch stem {
	case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$":
		return false
	}
	if strings.HasPrefix(stem, "COM") || strings.HasPrefix(stem, "LPT") {
		suffix := stem[3:]
		if utf8.RuneCountInString(suffix) == 1 && strings.Contains("123456789¹²³", suffix) {
			return false
		}
	}
	return true
}
func (s *Service) CreateUpload(ctx context.Context, p Principal, key string, r UploadRequest) (out Version, e error) {
	started := s.now()
	defer func() { s.observe(ctx, "media.uploads.create", started, e) }()
	ctx, finish, startErr := s.operation(ctx)
	if startErr != nil {
		return Version{}, startErr
	}
	defer finish()
	profile, ok := s.cfg.Profiles[r.Purpose]
	if !ok || r.Size < 1 || !digest.MatchString(r.SHA256) || (r.FileID != "" && !idOK(r.FileID)) {
		return out, ErrInput
	}
	if !validFilename(r.Filename) {
		return out, ErrFilenameInvalid
	}
	if !slices.Contains(profile.AllowedTypes, r.ContentType) {
		return out, ErrTypeNotAllowed
	}
	if r.Size > profile.MaxSize {
		return out, withLimit(ErrUploadTooLarge, profile.MaxSize)
	}
	var candidate Version
	created := false
	if r.ReuseExisting {
		if !validKey(key) || !p.Valid() {
			return out, ErrInput
		}
		if err := s.authorize(ctx, p, "media.uploads.create", Access{FileID: r.FileID, Purpose: r.Purpose, Owner: p, Protection: profile.Quarantine}); err != nil {
			return out, err
		}
		var err error
		candidate, err = s.chooseReuse(ctx, p, key, r, profile)
		if err != nil {
			return out, err
		}
	}
	var f File
	e = s.mutation(ctx, p, "media.uploads.create", r.FileID, key, r, func(tx Transaction) error {
		if e := tx.Lock("owner:" + hash(p)); e != nil {
			return e
		}
		if r.FileID != "" {
			if e := tx.Lock("file:" + r.FileID); e != nil {
				return e
			}
			var e error
			f, e = tx.File(r.FileID)
			if e != nil {
				return e
			}
			if f.Owner != p || f.Purpose != r.Purpose {
				return ErrDenied
			}
			if f.Disabled || f.Deleting {
				return ErrConflict
			}
		}
		return s.authorize(ctx, p, "media.uploads.create", Access{FileID: r.FileID, Purpose: r.Purpose, Owner: p, Protection: profile.Quarantine})
	}, func(tx Transaction) (any, error) {
		files, open, e := tx.Counts(p)
		if e != nil {
			return nil, e
		}
		if open >= s.cfg.MaxOpenUploads {
			return nil, withLimit(ErrOpenUploadsLimit, int64(s.cfg.MaxOpenUploads))
		}
		if r.FileID == "" && files >= s.cfg.MaxFilesPerOwner {
			return nil, withLimit(ErrFileLimit, int64(s.cfg.MaxFilesPerOwner))
		}
		if r.FileID == "" {
			f = File{ID: newID(), Owner: p, Purpose: r.Purpose, Revision: 1, CreatedAt: s.now().UTC().Truncate(time.Microsecond)}
		}
		if f.NextVersion >= s.cfg.MaxVersions {
			return nil, withLimit(ErrVersionLimit, int64(s.cfg.MaxVersions))
		}
		f.NextVersion++
		f.Revision++
		if e = tx.SaveFile(f); e != nil {
			return nil, e
		}
		v := Version{Shared: true, ID: newID(), FileID: f.ID, Number: f.NextVersion, Revision: 1, UploadID: newID(), Filename: r.Filename, ContentType: r.ContentType, Size: r.Size, SHA256: r.SHA256, State: "created", ExpiresAt: s.now().Add(s.cfg.UploadTTL), RetainUntil: s.now().Add(s.cfg.UnreferencedTTL), Profile: profile, References: []Reference{}}
		created = true
		if candidate.ID != "" {
			sourceFile, source, e := s.load(tx, candidate.ID)
			if e != nil {
				return nil, e
			}
			if s.reusable(sourceFile, source, p, r, profile) && source.ObjectID == candidate.ObjectID {
				if err := s.authorize(ctx, p, "media.files.read", access(sourceFile, source, nil)); err != nil {
					return nil, err
				}
				v.Reused = true
				v.ReuseSource = source.ID
				v.ReuseObject = source.ObjectID
				s.markObjectIssued(&v)
				v.TypeValidated = true
				v.State = "verifying"
			}
		}
		if e = tx.SaveVersion(v); e != nil {
			return nil, e
		}
		if v.Reused {
			if e = s.schedule(tx, v.ID, true); e != nil {
				return nil, e
			}
		}
		if e = s.emit(ctx, tx, p, "media.upload.created", v.ID, v.Revision, v.Profile.SchoolID, nil); e != nil {
			return nil, e
		}
		return v, nil
	}, &out)
	if e == nil && out.Reused {
		if !created {
			err := s.repo.Transaction(ctx, func(tx Transaction) error {
				f, v, err := s.load(tx, out.ID)
				if err != nil {
					return err
				}
				if err = s.authorize(ctx, p, "media.uploads.create", access(f, v, nil)); err != nil {
					return err
				}
				out = v
				return nil
			})
			return out, err
		}
		work, done, err := s.begin(ctx)
		if err != nil {
			return out, nil
		}
		defer done()
		v, err := s.reuseUpload(work, p, out.ID)
		if errors.Is(err, ErrUnavailable) || errors.Is(err, ErrCapacity) {
			return out, nil
		}
		return v, err
	}
	return out, e
}
func (s *Service) normalizeVersionProgress(v Version) Version {
	switch {
	case v.State == "awaiting_approval" || v.Approved || v.State == "ready":
		v.UploadedBytes = v.Size
	case terminal(v):
		v.UploadedBytes = 0
	case v.UploadedBytes > 0:
		v.UploadedBytes = min(v.UploadedBytes, s.staging.size(v.ID))
	}
	return v
}
func (s *Service) ListProfiles(ctx context.Context, p Principal) (ProfileCatalog, error) {
	out := ProfileCatalog{
		Profiles:         []ProfileSummary{},
		UploadTTLSeconds: int64(s.cfg.UploadTTL / time.Second),
		MaxArchiveFiles:  s.cfg.MaxArchiveFiles,
		MaxArchiveBytes:  s.cfg.MaxArchiveBytes,
	}
	if !p.Valid() {
		return out, ErrDenied
	}
	ctx, done, err := s.operation(ctx)
	if err != nil {
		return ProfileCatalog{}, err
	}
	defer done()
	names := make([]string, 0, len(s.cfg.Profiles))
	for name := range s.cfg.Profiles {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		prof := s.cfg.Profiles[name]
		e := s.authorize(ctx, p, "media.uploads.create", Access{Purpose: name, Owner: p, Protection: prof.Quarantine})
		if errors.Is(e, ErrDenied) {
			continue
		}
		if e != nil {
			return ProfileCatalog{}, e
		}
		out.Profiles = append(out.Profiles, ProfileSummary{
			Purpose:      name,
			Module:       prof.Module,
			AllowedTypes: slices.Clone(prof.AllowedTypes),
			MaxSize:      prof.MaxSize,
		})
	}
	return out, nil
}
func (s *Service) GetVersion(ctx context.Context, p Principal, id string) (out VersionView, e error) {
	started := s.now()
	defer func() { s.observe(ctx, "media.versions.read", started, e) }()
	return s.readVersion(ctx, p, id, false)
}
func (s *Service) readVersion(ctx context.Context, p Principal, id string, byUpload bool) (VersionView, error) {
	if !idOK(id) {
		return VersionView{}, ErrInput
	}
	ctx, finish, startErr := s.operation(ctx)
	if startErr != nil {
		return VersionView{}, startErr
	}
	defer finish()
	var f File
	var v Version
	e := s.repo.Transaction(ctx, func(tx Transaction) error { var err error; f, v, err = tx.ReadVersion(id, byUpload); return err })
	if e != nil {
		return VersionView{}, e
	}
	if e = s.authorize(ctx, p, "media.files.read", access(f, v, nil)); e != nil {
		return VersionView{}, e
	}
	out := VersionView{Version: s.normalizeVersionProgress(v), Desired: 3}
	if v.ObjectID != "" {
		stStarted := s.now()
		st, stErr := s.store.Status(ctx, s.cfg.Actor, v.ObjectID)
		if stErr == nil {
			out.StorageState = st.State
			out.Healthy = st.Healthy
			out.Desired = st.Desired
		} else {
			out.StorageState = "unavailable"
			s.observe(ctx, "media.storage.status", stStarted, storeError(stErr))
		}
	}
	return out, nil
}
func (s *Service) GetUpload(ctx context.Context, p Principal, id string) (VersionView, error) {
	return s.readVersion(ctx, p, id, true)
}
func (s *Service) GetFile(ctx context.Context, p Principal, id string) (FileView, error) {
	ctx, finish, startErr := s.operation(ctx)
	if startErr != nil {
		return FileView{}, startErr
	}
	defer finish()
	if !idOK(id) {
		return FileView{}, ErrInput
	}
	var out FileView
	err := s.repo.Transaction(ctx, func(tx Transaction) error { var err error; out, err = tx.ReadFile(id); return err })
	if err != nil {
		return FileView{}, err
	}
	if len(out.Versions) == 0 {
		return FileView{}, ErrUnavailable
	}
	if err = s.authorizeFile(ctx, p, "media.files.read", out.File, out.Versions); err != nil {
		return FileView{}, err
	}
	for i := range out.Versions {
		out.Versions[i] = s.normalizeVersionProgress(out.Versions[i])
	}
	return out, nil
}

// Record the earliest possible handle creation once, before the external call.
// Older versions without this bound keep their previously recorded deadline.
func (s *Service) markObjectIssued(v *Version) {
	if !v.ObjectIssued {
		v.HandleRetainLimit = s.now().Add(24 * time.Hour)
		v.ObjectIssued = true
	}
}

func (s *Service) extendPendingRetention(v *Version) {
	if terminal(*v) || v.Approved || v.State != "awaiting_approval" || liveReferences(*v) == 0 {
		return
	}
	if v.HandleRetainLimit.IsZero() {
		return
	}
	until := s.now().Add(s.cfg.PendingApprovalTTL)
	if until.After(v.HandleRetainLimit) {
		until = v.HandleRetainLimit
	}
	if until.After(v.RetainUntil) {
		v.RetainUntil = until
	}
}
func (s *Service) Approve(ctx context.Context, p Principal, id, key string) (Version, error) {
	ctx, finish, startErr := s.operation(ctx)
	if startErr != nil {
		return Version{}, startErr
	}
	defer finish()
	var out, v Version
	var f File
	e := s.mutation(ctx, p, "media.versions.approve", id, key, struct{}{}, func(tx Transaction) error {
		var e error
		f, v, e = s.load(tx, id)
		if e != nil {
			return e
		}
		return s.authorize(ctx, p, "media.versions.approve", access(f, v, nil))
	}, func(tx Transaction) (any, error) {
		if f.Disabled || f.Deleting || terminal(v) || v.State == "created" || v.State == "uploading" || v.State == "verifying" {
			return nil, ErrConflict
		}
		if !v.Approved {
			v.Approved = true
			v.State = "approved"
			v.UploadUntil = time.Time{}
			v.UploadGeneration++
			v.Revision++
			if e := tx.SaveVersion(v); e != nil {
				return nil, e
			}
			if e := s.schedule(tx, v.ID, true); e != nil {
				return nil, e
			}
			if e := s.emit(ctx, tx, p, "media.version.approved", v.ID, v.Revision, v.Profile.SchoolID, nil); e != nil {
				return nil, e
			}
		}
		return v, nil
	}, &out)
	return out, e
}
func (s *Service) Reject(ctx context.Context, p Principal, id, key, reason string) (Version, error) {
	ctx, done, err := s.operation(ctx)
	if err != nil {
		return Version{}, err
	}
	defer done()
	var out, v Version
	var f File
	if !idOK(id) || !ValidRejectionReason(reason) {
		return out, ErrInput
	}
	e := s.mutation(ctx, p, "media.versions.reject", id, key, RejectionRequest{Reason: reason}, func(tx Transaction) error {
		var e error
		f, v, e = s.load(tx, id)
		if e != nil {
			return e
		}
		return s.authorize(ctx, p, "media.versions.reject", access(f, v, nil))
	}, func(tx Transaction) (any, error) {
		if f.Disabled || f.Deleting || v.Approved || activeReferences(v) > 0 {
			return nil, ErrConflict
		}
		if v.State == "rejected" {
			if v.RejectionReason == reason {
				return v, nil
			}
			return nil, ErrConflict
		}
		if v.State != "awaiting_approval" {
			return nil, ErrConflict
		}
		if err := s.requireReclaimable(ctx, v); err != nil {
			return nil, err
		}
		v.State = "rejected"
		v.RejectionReason = reason
		v.ErrorCode = "media_rejected_" + reason
		if err := s.releaseBindings(ctx, tx, p, &v); err != nil {
			return nil, err
		}
		v.Revision++
		if e := tx.SaveVersion(v); e != nil {
			return nil, e
		}
		if e := s.schedule(tx, v.ID, true); e != nil {
			return nil, e
		}
		if e := s.emit(ctx, tx, p, "media.version.rejected", v.ID, v.Revision, v.Profile.SchoolID, nil); e != nil {
			return nil, e
		}
		return v, nil
	}, &out)
	return out, e
}

// Tombstones keep their original revision. Each newly released binding gets a
// distinct version revision and a matching event within the same transaction.
func (s *Service) releaseBindings(ctx context.Context, tx Transaction, p Principal, v *Version) error {
	for i := range v.References {
		r := &v.References[i]
		if r.State == "released" {
			continue
		}
		r.State = "released"
		r.Revision++
		v.Revision++
		if err := s.emit(ctx, tx, p, "media.reference.released", v.ID, v.Revision, v.Profile.SchoolID, r); err != nil {
			return err
		}
	}
	return nil
}
func (s *Service) CancelUpload(ctx context.Context, p Principal, id, key string) (Version, error) {
	ctx, finish, startErr := s.operation(ctx)
	if startErr != nil {
		return Version{}, startErr
	}
	defer finish()
	var out, v Version
	var f File
	e := s.mutation(ctx, p, "media.uploads.cancel", id, key, struct{}{}, func(tx Transaction) error {
		var e error
		v, e = tx.Upload(id)
		if e != nil {
			return e
		}
		f, v, e = s.load(tx, v.ID)
		if e != nil {
			return e
		}
		if f.Owner != p {
			return ErrDenied
		}
		return s.authorize(ctx, p, "media.uploads.cancel", access(f, v, nil))
	}, func(tx Transaction) (any, error) {
		if v.Approved || activeReferences(v) > 0 {
			return nil, ErrConflict
		}
		if !terminal(v) {
			if err := s.requireReclaimable(ctx, v); err != nil {
				return nil, err
			}
			v.State = "cancelled"
			v.UploadedBytes = 0
			v.ErrorCode = ""
			if err := s.releaseBindings(ctx, tx, p, &v); err != nil {
				return nil, err
			}
			v.Revision++
			if e := tx.SaveVersion(v); e != nil {
				return nil, e
			}
			if e := s.schedule(tx, v.ID, true); e != nil {
				return nil, e
			}
			if e := s.emit(ctx, tx, p, "media.upload.cancelled", v.ID, v.Revision, v.Profile.SchoolID, nil); e != nil {
				return nil, e
			}
		}
		return v, nil
	}, &out)
	if e == nil && out.ID != "" {
		s.staging.remove(out.ID)
	}
	return out, e
}
func (s *Service) SetFileState(ctx context.Context, p Principal, id, key string, revision int64, disabled bool) (FileView, error) {
	return s.changeFile(ctx, p, id, key, revision, disabled, false)
}
func (s *Service) DeleteFile(ctx context.Context, p Principal, id, key string, revision int64) (FileView, error) {
	return s.changeFile(ctx, p, id, key, revision, true, true)
}
func (s *Service) changeFile(ctx context.Context, p Principal, id, key string, revision int64, disabled, deleting bool) (FileView, error) {
	ctx, finish, startErr := s.operation(ctx)
	if startErr != nil {
		return FileView{}, startErr
	}
	defer finish()
	var out FileView
	var f File
	var vs []Version
	action := "media.files.disable"
	if deleting {
		action = "media.files.delete"
	}
	e := s.mutation(ctx, p, action, id, key, struct {
		Revision           int64
		Disabled, Deleting bool
	}{revision, disabled, deleting}, func(tx Transaction) error {
		if !idOK(id) {
			return ErrInput
		}
		if e := tx.Lock("file:" + id); e != nil {
			return e
		}
		var e error
		f, e = tx.File(id)
		if e != nil {
			return e
		}
		vs, e = tx.Versions(id)
		if e != nil {
			return e
		}
		if len(vs) == 0 {
			return ErrUnavailable
		}
		return s.authorizeFile(ctx, p, action, f, vs)
	}, func(tx Transaction) (any, error) {
		if f.Revision != revision || f.Deleting || f.Retired {
			return nil, ErrConflict
		}
		if deleting {
			for _, v := range vs {
				if liveReferences(v) > 0 {
					return nil, ErrConflict
				}
				if err := s.requireReclaimable(ctx, v); err != nil {
					return nil, err
				}
			}
		}
		f.Disabled = disabled
		f.Deleting = deleting
		f.Revision++
		if e := tx.SaveFile(f); e != nil {
			return nil, e
		}
		for n, v := range vs {
			if deleting && !terminal(v) {
				v.State = "deleting"
				v.UploadedBytes = 0
				v.Revision++
				if e := tx.SaveVersion(v); e != nil {
					return nil, e
				}
				vs[n] = v
			}
			if e := s.schedule(tx, v.ID, true); e != nil {
				return nil, e
			}
		}
		kind := action
		if !disabled && !deleting {
			kind = "media.files.enable"
		}
		if e := s.emit(ctx, tx, p, kind, f.ID, f.Revision, vs[0].Profile.SchoolID, nil); e != nil {
			return nil, e
		}
		return FileView{f, vs}, nil
	}, &out)
	if e == nil && deleting {
		for _, v := range out.Versions {
			s.staging.remove(v.ID)
		}
	}
	return out, e
}
func storeError(e error) error {
	switch {
	case e == nil:
		return nil
	case errors.Is(e, storage.ErrIntegrity):
		return ErrIntegrity
	case errors.Is(e, storage.ErrInput):
		return ErrInput
	case errors.Is(e, storage.ErrConflict), errors.Is(e, storage.ErrStale):
		return ErrConflict
	case errors.Is(e, storage.ErrCapacity):
		return ErrCapacity
	case errors.Is(e, storage.ErrDenied):
		return ErrDenied
	case errors.Is(e, storage.ErrNotFound):
		return ErrNotFound
	default:
		return ErrUnavailable
	}
}
