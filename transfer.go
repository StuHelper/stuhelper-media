package media

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	storage "github.com/StuHelper/stuhelper-storage"
	"io"
	"net/http"

	"time"
)

func streamMatches(src io.Reader, size int64, wantSHA256 string) bool {
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(src, size+1))
	if err != nil || n != size {
		return false
	}
	return hex.EncodeToString(h.Sum(nil)) == wantSHA256
}

func (s *Service) ensureObject(ctx context.Context, v Version) (string, error) {
	if v.ObjectID != "" && (!v.Reused || v.State != "verifying") {
		return v.ObjectID, nil
	}
	if !v.ObjectIssued {
		return "", ErrConflict
	}
	request := storage.CreateRequest{Deduplicate: v.Shared, ReuseFrom: v.ReuseObject, ClientKey: "media:" + v.ID, Size: v.Size, SHA256: v.SHA256, Protection: v.Profile.Quarantine}
	if v.Prepared {
		request.ReserveFor = &v.Profile.Published
	}
	st, e := s.store.Create(ctx, s.cfg.Actor, "media-create:"+v.ID, request)
	if e != nil && st.ID == "" {
		return "", storeError(e)
	}
	storeErr := e
	receipt, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	e = s.repo.Transaction(receipt, func(tx Transaction) error {
		_, current, e := s.load(tx, v.ID)
		if e != nil {
			return e
		}
		if current.ObjectID != "" && current.ObjectID != st.ID {
			return ErrConflict
		}
		current.ObjectID = st.ID
		return tx.SaveVersion(current)
	})
	if e != nil {
		return st.ID, e
	}
	return st.ID, storeError(storeErr)
}

// Keep the ingress limit error even when storage maps a reader failure to its
// own error. Only size+1 bytes are necessary to distinguish a long request.
type uploadReader struct {
	io.LimitedReader
	err error
}

func (r *uploadReader) Read(p []byte) (int, error) {
	n, err := r.LimitedReader.Read(p)
	if err != nil && err != io.EOF {
		r.err = err
	}
	return n, err
}
func (s *Service) Upload(ctx context.Context, p Principal, id, key string, src io.Reader) (ret Version, retErr error) {
	started := s.now()
	defer func() { s.observe(ctx, "media.uploads.write", started, retErr) }()
	if !idOK(id) || !validKey(key) || src == nil {
		return Version{}, ErrInput
	}
	work, done, e := s.begin(ctx)
	if e != nil {
		return Version{}, e
	}
	defer done()
	ctx = work
	var v Version
	var complete bool
	var probeStorage, retry bool
	e = s.repo.Transaction(ctx, func(tx Transaction) error {
		initial, e := tx.Upload(id)
		if e != nil {
			return e
		}
		f, current, e := s.load(tx, initial.ID)
		if e != nil {
			return e
		}
		v = current
		if f.Owner != p {
			return ErrDenied
		}
		if e = s.authorize(ctx, p, "media.uploads.write", access(f, v, nil)); e != nil {
			return e
		}
		if f.Disabled || f.Deleting || terminal(v) {
			return ErrConflict
		}
		if v.Reused {
			return ErrConflict
		}
		if v.UploadKey != "" && v.UploadKey != key {
			return ErrConflict
		}
		if v.State == "awaiting_approval" || v.Approved {
			v.UploadedBytes = v.Size
			complete = true
			return nil
		}
		if !v.ExpiresAt.After(s.now()) {
			return ErrExpired
		}
		if v.UploadUntil.After(s.now()) {
			return ErrConflict
		}
		retry = v.UploadKey != ""
		probeStorage = (v.State == "verifying" || v.State == "uploading") && v.ObjectIssued && v.TypeValidated
		v.State = "uploading"
		v.UploadedBytes = 0
		v.ChunkKey = ""
		v.ChunkOffset = 0
		v.ChunkSize = 0
		v.ChunkSHA256 = ""
		v.UploadGeneration++
		v.UploadKey = key
		v.UploadUntil = s.now().Add(s.cfg.OperationTimeout + time.Second)
		v.Revision++
		if err := tx.SaveVersion(v); err != nil {
			return err
		}
		return s.schedule(tx, v.ID, true)
	})
	if e != nil {
		return v, e
	}
	if complete {
		if !streamMatches(src, v.Size, v.SHA256) {
			return Version{}, ErrConflict
		}
		return v, nil
	}
	s.staging.remove(v.ID)
	// Hold the same generation through observation and ingest. A status failure
	// leaves the outcome unconfirmed and does not start a second transfer.
	alreadyStored := false
	if probeStorage {
		var object string
		object, e = s.ensureObject(ctx, v)
		if e == nil {
			var status storage.Status
			status, e = s.store.Status(ctx, s.cfg.Actor, object)
			e = storeError(e)
			alreadyStored = e == nil && status.Healthy > 0
		}
	}
	if e == nil && alreadyStored {
		if !streamMatches(src, v.Size, v.SHA256) {
			e = ErrConflict
		}
	} else if e == nil {
		e = s.ingestUpload(ctx, p, v, src)
		if retry && (errors.Is(e, ErrIntegrity) || errors.Is(e, ErrType)) {
			e = ErrConflict
		}
	}
	finish, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	var out Version
	var fencedErr error
	save := s.repo.Transaction(finish, func(tx Transaction) error {
		f, current, err := s.load(tx, v.ID)
		if err != nil {
			return err
		}
		out = current
		if current.UploadGeneration != v.UploadGeneration || terminal(current) || f.Disabled || f.Deleting || current.Approved || current.State != "uploading" || !current.UploadUntil.After(s.now()) {
			if current.UploadGeneration == v.UploadGeneration && !current.UploadUntil.IsZero() && (terminal(current) || f.Disabled || f.Deleting) {
				current.UploadUntil = time.Time{}
				out = current
				if err = tx.SaveVersion(current); err != nil {
					return err
				}
			}
			switch {
			case current.State == "expired":
				fencedErr = ErrExpired
			case terminal(current) || f.Disabled || f.Deleting || current.UploadGeneration != v.UploadGeneration || current.Approved || current.State != "uploading":
				fencedErr = ErrConflict
			case e != nil:
				fencedErr = e
			default:
				fencedErr = ErrUnavailable
			}
			return nil
		}
		current.UploadUntil = time.Time{}
		current.Revision++
		switch {
		case e == nil:
			current.State = "awaiting_approval"
			current.UploadedBytes = current.Size
			current.ErrorCode = ""
			s.extendPendingRetention(&current)
		case errors.Is(e, ErrUploadTooLarge):
			current.State = "created"
			current.UploadedBytes = 0
			current.TypeValidated = false
			current.ErrorCode = e.Error()
		case errors.Is(e, ErrIntegrity) || errors.Is(e, ErrType):
			current.State = "rejected"
			current.UploadedBytes = 0
			current.ErrorCode = e.Error()
		default:
			current.State = "verifying"
			current.ErrorCode = "media_upload_result_unconfirmed"
		}
		out = current
		if err = tx.SaveVersion(current); err != nil {
			return err
		}
		if err = s.schedule(tx, v.ID, true); err != nil {
			return err
		}
		return s.emit(ctx, tx, p, "media.upload.checked", v.ID, current.Revision, v.Profile.SchoolID, nil)
	})
	if save != nil {
		return out, save
	}
	if fencedErr != nil {
		return out, fencedErr
	}
	return out, e
}

func (s *Service) ingestUpload(ctx context.Context, p Principal, v Version, src io.Reader) error {
	input := &uploadReader{LimitedReader: io.LimitedReader{R: src, N: v.Size + 1}}
	prefix, e := io.ReadAll(io.LimitReader(input, 3072))
	if input.N == 0 {
		e = ErrTooLarge
	}
	if e == nil && !matchesContentType(prefix, v.ContentType) {
		e = ErrType
	}
	if e == nil {
		e = s.repo.Transaction(ctx, func(tx Transaction) error {
			f, current, err := s.load(tx, v.ID)
			if err != nil {
				return err
			}
			if terminal(current) || f.Disabled || f.Deleting || current.UploadGeneration != v.UploadGeneration || current.State != "uploading" || !current.UploadUntil.After(s.now()) {
				return ErrConflict
			}
			if err = s.authorize(ctx, p, "media.uploads.write", access(f, current, nil)); err != nil {
				return err
			}
			current.TypeValidated = true
			s.markObjectIssued(&current)
			v = current
			return tx.SaveVersion(current)
		})
	}
	var object string
	if e == nil {
		object, e = s.ensureObject(ctx, v)
	}
	if e == nil {
		e = s.repo.Transaction(ctx, func(tx Transaction) error {
			f, current, e := s.load(tx, v.ID)
			if e != nil {
				return e
			}
			if terminal(current) || f.Disabled || f.Deleting || current.UploadGeneration != v.UploadGeneration || current.State != "uploading" || !current.UploadUntil.After(s.now()) {
				return ErrConflict
			}
			return s.authorize(ctx, p, "media.uploads.write", access(f, current, nil))
		})
	}
	if e == nil {
		_, err := s.store.Ingest(ctx, s.cfg.Actor, object, "media-ingest:"+v.ID, io.MultiReader(bytes.NewReader(prefix), input))
		e = storeError(err)
	}
	var limit *http.MaxBytesError
	if input.N == 0 || errors.As(input.err, &limit) {
		e = ErrTooLarge
	}
	return e
}

func (s *Service) AppendUpload(ctx context.Context, p Principal, id, key string, offset int64, src io.Reader) (Version, error) {
	if !idOK(id) || !validKey(key) || offset < 0 || src == nil {
		return Version{}, ErrInput
	}
	work, done, e := s.begin(ctx)
	if e != nil {
		return Version{}, e
	}
	defer done()
	ctx = work
	var v Version
	var replayCandidate bool
	e = s.repo.Transaction(ctx, func(tx Transaction) error {
		initial, e := tx.Upload(id)
		if e != nil {
			return e
		}
		f, current, e := s.load(tx, initial.ID)
		if e != nil {
			return e
		}
		v = current
		if f.Owner != p {
			return ErrDenied
		}
		if e = s.authorize(ctx, p, "media.uploads.write", access(f, v, nil)); e != nil {
			return e
		}
		if f.Disabled || f.Deleting || terminal(v) || v.Reused {
			return ErrConflict
		}
		physical := s.staging.size(v.ID)
		if v.ChunkKey != "" && v.ChunkKey == key && (v.Approved || v.State == "awaiting_approval" || physical >= v.ChunkOffset+v.ChunkSize) {
			replayCandidate = true
			return nil
		}
		if v.State == "awaiting_approval" || v.Approved {
			return ErrConflict
		}
		if !v.ExpiresAt.After(s.now()) {
			return ErrExpired
		}
		if v.UploadUntil.After(s.now()) {
			return ErrConflict
		}
		if offset >= v.Size {
			return ErrInput
		}
		actual := min(v.UploadedBytes, physical)
		if offset != actual {
			return ErrConflict
		}
		v.State = "uploading"
		v.UploadedBytes = actual
		if offset == 0 {
			v.TypeValidated = false
			v.ChunkKey = ""
		}
		v.UploadGeneration++
		v.UploadUntil = s.now().Add(s.cfg.OperationTimeout + time.Second)
		v.Revision++
		if e = tx.SaveVersion(v); e != nil {
			return e
		}
		return s.schedule(tx, v.ID, true)
	})
	if e != nil {
		return Version{}, e
	}
	if replayCandidate {
		if v.ChunkOffset != offset {
			return Version{}, ErrConflict
		}
		hasher := sha256.New()
		n, readErr := io.Copy(hasher, io.LimitReader(src, v.Size-offset+1))
		if readErr != nil {
			var maxBytes *http.MaxBytesError
			if errors.As(readErr, &maxBytes) {
				return Version{}, readErr
			}
			return Version{}, ErrUnavailable
		}
		if n != v.ChunkSize || hex.EncodeToString(hasher.Sum(nil)) != v.ChunkSHA256 {
			return Version{}, ErrConflict
		}
		return s.normalizeVersionProgress(v), nil
	}

	newOffset, chunkSize, chunkSHA, prefix, e := s.staging.appendChunk(ctx, v.ID, offset, v.Size, src)
	typeValidated := offset > 0 && v.TypeValidated
	if e == nil && !typeValidated && (newOffset >= 512 || newOffset == v.Size) {
		typeValidated = matchesContentType(prefix, v.ContentType)
		if !typeValidated && (newOffset >= 3072 || newOffset == v.Size || http.DetectContentType(prefix) != "application/zip") {
			e = ErrType
		}
	}

	if e == nil && newOffset < v.Size {
		finish, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		var out Version
		saveErr := s.repo.Transaction(finish, func(tx Transaction) error {
			_, current, err := s.load(tx, v.ID)
			if err != nil {
				return err
			}
			out = current
			if current.UploadGeneration != v.UploadGeneration || current.State != "uploading" || !current.UploadUntil.After(s.now()) {
				return ErrConflict
			}
			current.State = "uploading"
			current.UploadedBytes = newOffset
			current.TypeValidated = typeValidated
			current.UploadUntil = time.Time{}
			current.ErrorCode = ""
			current.ChunkKey = key
			current.ChunkOffset = offset
			current.ChunkSize = chunkSize
			current.ChunkSHA256 = chunkSHA
			current.Revision++
			out = current
			return tx.SaveVersion(current)
		})
		if saveErr != nil {
			return out, saveErr
		}
		return out, nil
	}

	completedBytes := e == nil && newOffset == v.Size
	if completedBytes {
		verifiedFile, verifyErr := s.staging.openVerified(ctx, v.ID, v.Size, v.SHA256)
		if verifyErr != nil {
			e = verifyErr
		} else {
			defer verifiedFile.Close()
			e = s.ingestUpload(ctx, p, v, verifiedFile)
		}
	}

	finish, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	var out Version
	save := s.repo.Transaction(finish, func(tx Transaction) error {
		_, current, err := s.load(tx, v.ID)
		if err != nil {
			return err
		}
		out = current
		if current.UploadGeneration != v.UploadGeneration || current.State != "uploading" || !current.UploadUntil.After(s.now()) {
			return ErrConflict
		}
		current.UploadUntil = time.Time{}
		current.Revision++
		switch {
		case e == nil:
			current.State = "awaiting_approval"
			s.extendPendingRetention(&current)
			current.UploadedBytes = current.Size
			current.ErrorCode = ""
			current.ChunkKey = key
			current.ChunkOffset = offset
			current.ChunkSize = chunkSize
			current.ChunkSHA256 = chunkSHA
			out = current
			if err = tx.SaveVersion(current); err != nil {
				return err
			}
			if err = s.schedule(tx, v.ID, true); err != nil {
				return err
			}
			return s.emit(finish, tx, p, "media.upload.checked", v.ID, current.Revision, v.Profile.SchoolID, nil)
		case errors.Is(e, ErrIntegrity) || errors.Is(e, ErrType):
			current.State = "rejected"
			current.UploadedBytes = 0
			current.ErrorCode = e.Error()
			out = current
			if err = tx.SaveVersion(current); err != nil {
				return err
			}
			if err = s.schedule(tx, v.ID, true); err != nil {
				return err
			}
			return s.emit(finish, tx, p, "media.upload.checked", v.ID, current.Revision, v.Profile.SchoolID, nil)
		case completedBytes && current.ObjectIssued:
			current.State = "verifying"
			current.UploadedBytes = current.Size
			current.ErrorCode = "media_upload_result_unconfirmed"
			out = current
			if err = tx.SaveVersion(current); err != nil {
				return err
			}
			if err = s.schedule(tx, v.ID, true); err != nil {
				return err
			}
			return s.emit(finish, tx, p, "media.upload.checked", v.ID, current.Revision, v.Profile.SchoolID, nil)
		default:
			current.State = "uploading"
			current.UploadedBytes = offset
			out = current
			return tx.SaveVersion(current)
		}
	})
	if save != nil {
		return out, save
	}
	if out.State != "uploading" {
		s.staging.remove(v.ID)
	}
	return out, e
}

type checkedWriter struct {
	check   func() error
	dst     io.Writer
	checked bool
}

func (w *checkedWriter) Write(b []byte) (int, error) {
	if !w.checked {
		if e := w.check(); e != nil {
			return 0, e
		}
		w.checked = true
	}
	return w.dst.Write(b)
}

// Only a currently active business reference can deliver content. Storage
// verifies the complete bytes before Write, then this guard rechecks access.
func (s *Service) Download(ctx context.Context, p Principal, id string, dst io.Writer) error {
	if !idOK(id) || dst == nil {
		return ErrInput
	}
	ctx, done, e := s.begin(ctx)
	if e != nil {
		return e
	}
	defer done()
	return s.download(ctx, p, id, dst)
}

// download reuses an already reserved transfer slot for an archive entry.
func (s *Service) download(ctx context.Context, p Principal, id string, dst io.Writer) error {
	var object string
	var expected Protection
	check := func() error {
		v, err := s.ReferenceVersion(ctx, p, id)
		if err != nil {
			return err
		}
		if object != "" && object != v.ObjectID {
			return ErrConflict
		}
		object = v.ObjectID
		expected = v.Profile.Published
		st, err := s.store.Status(ctx, s.cfg.Actor, object)
		if err != nil {
			return storeError(err)
		}
		if st.Protection != expected {
			return ErrDenied
		}
		return nil
	}
	if e := check(); e != nil {
		return e
	}
	e := s.store.Download(ctx, s.cfg.Actor, object, &checkedWriter{check: check, dst: dst})
	// A business denial from the final writer is already a media error.
	if errors.Is(e, ErrDenied) || errors.Is(e, ErrConflict) {
		return e
	}
	return storeError(e)
}

// ReviewDownload serves complete, verified bytes to a separately authorized
// reviewer. It never activates a reference or grants ordinary download access.
func (s *Service) ReviewDownload(ctx context.Context, p Principal, id string, dst io.Writer) error {
	if !idOK(id) || dst == nil {
		return ErrInput
	}
	ctx, done, e := s.begin(ctx)
	if e != nil {
		return e
	}
	defer done()
	var object string
	var quarantine, published Protection
	var authAccess Access
	var revision int64
	check := func() error {
		var f File
		var v Version
		e := s.repo.Transaction(ctx, func(tx Transaction) error { var err error; f, v, err = tx.ReadVersion(id, false); return err })
		if e != nil {
			return e
		}
		authAccess = access(f, v, nil)
		if e = s.authorize(ctx, p, "media.versions.review", authAccess); e != nil {
			return e
		}
		if f.Disabled || f.Deleting || terminal(v) || (v.State != "awaiting_approval" && !v.Approved) || v.ObjectID == "" {
			return ErrDenied
		}
		if object != "" && object != v.ObjectID {
			return ErrConflict
		}
		object = v.ObjectID
		revision = v.Revision
		quarantine = v.Profile.Quarantine
		published = v.Profile.Published
		status, e := s.store.Status(ctx, s.cfg.Actor, object)
		if e != nil {
			return storeError(e)
		}
		if status.Protection != quarantine && status.Protection != published {
			return ErrDenied
		}
		if status.Protection != authAccess.Protection {
			actual := authAccess
			actual.Protection = status.Protection
			if e = s.authorize(ctx, p, "media.versions.review", actual); e != nil {
				return e
			}
		}
		return nil
	}
	if e := check(); e != nil {
		return e
	}
	auditRead := func() error {
		if err := check(); err != nil {
			return err
		}
		return s.repo.Transaction(ctx, func(tx Transaction) error {
			return tx.Audit(Event{ID: newID(), Type: "media.version.reviewed.v1", Subject: id, Actor: p, Time: s.now(), Data: EventData{Revision: revision}})
		})
	}
	e = s.store.ReviewDownload(ctx, s.cfg.Actor, object, &checkedWriter{check: auditRead, dst: dst})
	if errors.Is(e, ErrDenied) || errors.Is(e, ErrConflict) {
		return e
	}
	return storeError(e)
}
