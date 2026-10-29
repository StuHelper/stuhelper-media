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
	repo   Repository
	auth   Authorizer
	store  Store
	cfg    Config
	now    func() time.Time
	slots  chan struct{}
	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.Mutex
	closed bool
	active sync.WaitGroup
}

func New(r Repository, a Authorizer, store Store, c Config) (*Service, error) {
	if r == nil || a == nil || store == nil || !c.Actor.Valid() || len(c.Profiles) == 0 || len(c.Profiles) > 64 || c.UploadTTL < time.Minute || c.UploadTTL > 24*time.Hour || c.UnreferencedTTL < c.UploadTTL || c.UnreferencedTTL > 24*time.Hour || c.OperationTimeout < time.Second || c.OperationTimeout > 5*time.Minute || c.ParallelTransfers < 1 || c.ParallelTransfers > 16 || c.MaxOpenUploads < 1 || c.MaxOpenUploads > 100 || c.MaxFilesPerOwner < 1 || c.MaxFilesPerOwner > 10000 || c.MaxVersions < 1 || c.MaxVersions > 100 || c.MaxReferences < 1 || c.MaxReferences > 100 || c.MaxAttempts < 1 || c.MaxAttempts > 100 {
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
	profiles := make(map[string]Profile, len(c.Profiles))
	for name, p := range c.Profiles {
		if !idOK(name) || !idOK(p.Module) || !p.Quarantine.Valid() || p.Quarantine.Public || !p.Published.Valid() || p.Published.Scope != p.Quarantine.Scope || (!p.Published.Public && p.Published != p.Quarantine) || p.MaxSize < 1 || p.MaxSize > 1<<30 || len(p.AllowedTypes) == 0 || len(p.AllowedTypes) > 32 {
			return nil, ErrInput
		}
		for _, v := range p.AllowedTypes {
			typ, params, e := mime.ParseMediaType(v)
			if e != nil || typ != v || len(params) != 0 {
				return nil, ErrInput
			}
		}
		p.AllowedTypes = slices.Clone(p.AllowedTypes)
		profiles[name] = p
	}
	c.Profiles = profiles
	now := c.Clock
	if now == nil {
		now = time.Now
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Service{repo: r, auth: a, store: store, cfg: c, now: now, slots: make(chan struct{}, c.ParallelTransfers), ctx: ctx, cancel: cancel}, nil
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
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (s *Service) begin(ctx context.Context) (context.Context, func(), error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, nil, ErrUnavailable
	}
	select {
	case s.slots <- struct{}{}:
	default:
		s.mu.Unlock()
		return nil, nil, ErrCapacity
	}
	s.active.Add(1)
	s.mu.Unlock()
	work, cancel := context.WithTimeout(ctx, s.cfg.OperationTimeout)
	stop := context.AfterFunc(s.ctx, cancel)
	return work, func() { stop(); cancel(); <-s.slots; s.active.Done() }, nil
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
func access(f File, v Version, r *Reference) Access {
	return Access{FileID: f.ID, VersionID: v.ID, Purpose: f.Purpose, Owner: f.Owner, Protection: v.Profile.Published, Reference: r}
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
		old, e := tx.Replay(op)
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
		if e = tx.SaveReplay(Replay{Key: op, Digest: fingerprint, Result: b}); e != nil {
			return e
		}
		return json.Unmarshal(b, out)
	})
}
func (s *Service) emit(tx Transaction, p Principal, kind, id string, revision int64) error {
	return tx.Event(Event{ID: newID(), Type: kind + ".v1", Subject: id, Revision: revision, Time: s.now(), Actor: p})
}
func (s *Service) schedule(tx Transaction, id string, reset bool) error {
	j, e := tx.Job(id)
	if e != nil && !errors.Is(e, ErrNotFound) {
		return e
	}
	if j.State == "running" {
		return nil
	}
	if j.State == "blocked" && !reset {
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
func (s *Service) save(tx Transaction, p Principal, v Version, kind string) error {
	v.Revision++
	if e := tx.SaveVersion(v); e != nil {
		return e
	}
	if e := s.schedule(tx, v.ID, true); e != nil {
		return e
	}
	return s.emit(tx, p, kind, v.ID, v.Revision)
}
func validFilename(v string) bool {
	return utf8.ValidString(v) && len(v) > 0 && len(v) <= 240 && v != "." && v != ".." && !strings.ContainsAny(v, "/\\") && strings.IndexFunc(v, unicode.IsControl) < 0
}
func (s *Service) CreateUpload(ctx context.Context, p Principal, key string, r UploadRequest) (Version, error) {
	var out Version
	profile, ok := s.cfg.Profiles[r.Purpose]
	if !ok || !validFilename(r.Filename) || !slices.Contains(profile.AllowedTypes, r.ContentType) || r.Size < 1 || r.Size > profile.MaxSize || !digest.MatchString(r.SHA256) || (r.FileID != "" && !idOK(r.FileID)) {
		return out, ErrInput
	}
	var f File
	e := s.mutation(ctx, p, "media.uploads.create", r.FileID, key, r, func(tx Transaction) error {
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
		return s.authorize(ctx, p, "media.uploads.create", Access{FileID: r.FileID, Purpose: r.Purpose, Owner: p, Protection: profile.Published})
	}, func(tx Transaction) (any, error) {
		files, open, e := tx.Counts(p)
		if e != nil {
			return nil, e
		}
		if open >= s.cfg.MaxOpenUploads || (r.FileID == "" && files >= s.cfg.MaxFilesPerOwner) {
			return nil, ErrCapacity
		}
		if r.FileID == "" {
			f = File{ID: newID(), Owner: p, Purpose: r.Purpose, Revision: 1, CreatedAt: s.now()}
		}
		if f.NextVersion >= s.cfg.MaxVersions {
			return nil, ErrCapacity
		}
		f.NextVersion++
		f.Revision++
		if e = tx.SaveFile(f); e != nil {
			return nil, e
		}
		v := Version{Shared: true, ID: newID(), FileID: f.ID, Number: f.NextVersion, Revision: 1, UploadID: newID(), Filename: r.Filename, ContentType: r.ContentType, Size: r.Size, SHA256: r.SHA256, State: "created", ExpiresAt: s.now().Add(s.cfg.UploadTTL), RetainUntil: s.now().Add(s.cfg.UnreferencedTTL), Profile: profile, References: []Reference{}}
		if r.ReuseExisting {
			source, e := s.chooseReuse(ctx, tx, p, r, profile)
			if e != nil {
				return nil, e
			}
			if source.ID != "" {
				v.Reused = true
				v.ReuseSource = source.ID
				v.ReuseObject = source.ObjectID
				v.ObjectIssued = true
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
		if e = s.emit(tx, p, "media.upload.created", v.ID, v.Revision); e != nil {
			return nil, e
		}
		return v, nil
	}, &out)
	if e == nil && out.Reused {
		work, done, err := s.begin(ctx)
		if err != nil {
			return out, err
		}
		defer done()
		return s.reuseUpload(work, p, out.ID)
	}
	return out, e
}
func (s *Service) GetVersion(ctx context.Context, p Principal, id string) (VersionView, error) {
	var v Version
	e := s.repo.Transaction(ctx, func(tx Transaction) error {
		f, current, e := s.load(tx, id)
		if e != nil {
			return e
		}
		v = current
		return s.authorize(ctx, p, "media.files.read", access(f, v, nil))
	})
	out := VersionView{Version: v, Desired: 3}
	if e != nil {
		return out, e
	}
	if v.ObjectID != "" {
		st, e := s.store.Status(ctx, s.cfg.Actor, v.ObjectID)
		if e == nil {
			out.StorageState = st.State
			out.Healthy = st.Healthy
			out.Desired = st.Desired
		} else {
			out.StorageState = "unavailable"
		}
	}
	return out, nil
}
func (s *Service) GetUpload(ctx context.Context, p Principal, id string) (VersionView, error) {
	var v Version
	e := s.repo.Transaction(ctx, func(tx Transaction) error { var e error; v, e = tx.Upload(id); return e })
	if e != nil {
		return VersionView{}, e
	}
	return s.GetVersion(ctx, p, v.ID)
}
func (s *Service) GetFile(ctx context.Context, p Principal, id string) (FileView, error) {
	var out FileView
	e := s.repo.Transaction(ctx, func(tx Transaction) error {
		if !idOK(id) {
			return ErrInput
		}
		if e := tx.Lock("file:" + id); e != nil {
			return e
		}
		f, e := tx.File(id)
		if e != nil {
			return e
		}
		vs, e := tx.Versions(id)
		if e != nil {
			return e
		}
		if len(vs) == 0 {
			return ErrUnavailable
		}
		if e = s.authorize(ctx, p, "media.files.read", access(f, vs[0], nil)); e != nil {
			return e
		}
		out = FileView{f, vs}
		return nil
	})
	return out, e
}
func (s *Service) Approve(ctx context.Context, p Principal, id, key string) (Version, error) {
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
			v.Revision++
			if e := tx.SaveVersion(v); e != nil {
				return nil, e
			}
			if e := s.schedule(tx, v.ID, true); e != nil {
				return nil, e
			}
			if e := s.emit(tx, p, "media.version.approved", v.ID, v.Revision); e != nil {
				return nil, e
			}
		}
		return v, nil
	}, &out)
	return out, e
}
func (s *Service) CancelUpload(ctx context.Context, p Principal, id, key string) (Version, error) {
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
			v.State = "cancelled"
			v.ErrorCode = ""
			for n := range v.References {
				v.References[n].State = "released"
				v.References[n].Revision++
			}
			v.Revision++
			if e := tx.SaveVersion(v); e != nil {
				return nil, e
			}
			if e := s.schedule(tx, v.ID, true); e != nil {
				return nil, e
			}
			if e := s.emit(tx, p, "media.upload.cancelled", v.ID, v.Revision); e != nil {
				return nil, e
			}
		}
		return v, nil
	}, &out)
	return out, e
}
func (s *Service) SetFileState(ctx context.Context, p Principal, id, key string, revision int64, disabled bool) (FileView, error) {
	return s.changeFile(ctx, p, id, key, revision, disabled, false)
}
func (s *Service) DeleteFile(ctx context.Context, p Principal, id, key string, revision int64) (FileView, error) {
	return s.changeFile(ctx, p, id, key, revision, true, true)
}
func (s *Service) changeFile(ctx context.Context, p Principal, id, key string, revision int64, disabled, deleting bool) (FileView, error) {
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
		return s.authorize(ctx, p, action, access(f, vs[0], nil))
	}, func(tx Transaction) (any, error) {
		if f.Revision != revision || f.Deleting {
			return nil, ErrConflict
		}
		if deleting {
			for _, v := range vs {
				if liveReferences(v) > 0 {
					return nil, ErrConflict
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
		if e := s.emit(tx, p, action, f.ID, f.Revision); e != nil {
			return nil, e
		}
		return FileView{f, vs}, nil
	}, &out)
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
