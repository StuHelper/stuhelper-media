package media

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	storage "github.com/StuHelper/stuhelper-storage"
	"io"
	"mime"
	"net/http"
	"time"
)

func (s *Service) ensureObject(ctx context.Context, v Version) (string, error) {
	if v.ObjectID != "" && (!v.Reused || v.State != "verifying") {
		return v.ObjectID, nil
	}
	if !v.ObjectIssued {
		return "", ErrConflict
	}
	st, e := s.store.Create(ctx, s.cfg.Actor, "media-create:"+v.ID, storage.CreateRequest{Deduplicate: v.Shared, ReuseFrom: v.ReuseObject, ClientKey: "media:" + v.ID, Size: v.Size, SHA256: v.SHA256, Protection: v.Profile.Quarantine})
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
func (s *Service) Upload(ctx context.Context, p Principal, id, key string, src io.Reader) (Version, error) {
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
	var reused bool
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
		if v.State == "awaiting_approval" || v.Approved {
			v.UploadedBytes = v.Size
			complete = true
			return nil
		}
		if v.Reused {
			reused = true
			return nil
		}
		if !v.ExpiresAt.After(s.now()) {
			return ErrExpired
		}
		if v.UploadUntil.After(s.now()) {
			return ErrConflict
		}
		v.State = "uploading"
		v.UploadedBytes = 0
		v.ChunkKey = ""
		v.ChunkOffset = 0
		v.ChunkSize = 0
		v.ChunkSHA256 = ""
		v.UploadGeneration++
		v.UploadUntil = s.now().Add(s.cfg.OperationTimeout + time.Second)
		v.Revision++
		if e = tx.SaveVersion(v); e != nil {
			return e
		}
		return s.schedule(tx, v.ID, true)
	})
	if e != nil || complete {
		return v, e
	}
	if reused {
		return s.reuseUpload(ctx, p, v.ID)
	}
	s.staging.remove(v.ID)
	prefix, e := io.ReadAll(io.LimitReader(src, 512))
	if e == nil {
		detected, _, parse := mime.ParseMediaType(http.DetectContentType(prefix))
		if parse != nil || detected != v.ContentType {
			e = ErrType
		}
	}
	if e == nil {
		e = s.repo.Transaction(ctx, func(tx Transaction) error {
			f, current, err := s.load(tx, v.ID)
			if err != nil {
				return err
			}
			if terminal(current) || f.Disabled || f.Deleting || current.UploadGeneration != v.UploadGeneration {
				return ErrConflict
			}
			if err = s.authorize(ctx, p, "media.uploads.write", access(f, current, nil)); err != nil {
				return err
			}
			current.TypeValidated = true
			current.ObjectIssued = true
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
			if terminal(current) || f.Disabled || f.Deleting || current.UploadGeneration != v.UploadGeneration {
				return ErrConflict
			}
			return s.authorize(ctx, p, "media.uploads.write", access(f, current, nil))
		})
	}
	if e == nil {
		_, err := s.store.Ingest(ctx, s.cfg.Actor, object, "media-ingest:"+v.ID, io.MultiReader(bytes.NewReader(prefix), src))
		e = storeError(err)
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
		if current.UploadGeneration != v.UploadGeneration || terminal(current) {
			return nil
		}
		current.UploadUntil = time.Time{}
		current.Revision++
		switch {
		case e == nil:
			current.State = "awaiting_approval"
			current.UploadedBytes = current.Size
			current.ErrorCode = ""
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
		return s.emit(tx, p, "media.upload.checked", v.ID, current.Revision)
	})
	if save != nil {
		return out, save
	}
	return out, e
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
		if v.ChunkKey != "" && v.ChunkKey == key {
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
		actual := s.staging.size(v.ID)
		if offset != actual {
			return ErrConflict
		}
		v.State = "uploading"
		v.UploadedBytes = actual
		v.UploadGeneration++
		v.UploadUntil = s.now().Add(s.cfg.OperationTimeout + time.Second)
		v.Revision++
		if e = tx.SaveVersion(v); e != nil {
			return e
		}
		return s.schedule(tx, v.ID, true)
	})
	if e != nil {
		return s.normalizeVersionProgress(v), e
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
	typeValidated := v.TypeValidated
	if e == nil && (!typeValidated || offset == 0) && (newOffset >= 512 || newOffset == v.Size) {
		detected, _, parse := mime.ParseMediaType(http.DetectContentType(prefix))
		if parse != nil || detected != v.ContentType {
			e = ErrType
		} else {
			typeValidated = true
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
			if current.UploadGeneration != v.UploadGeneration || terminal(current) {
				s.staging.remove(v.ID)
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
			e = s.repo.Transaction(ctx, func(tx Transaction) error {
				f, current, err := s.load(tx, v.ID)
				if err != nil {
					return err
				}
				if terminal(current) || f.Disabled || f.Deleting || current.UploadGeneration != v.UploadGeneration {
					return ErrConflict
				}
				if err = s.authorize(ctx, p, "media.uploads.write", access(f, current, nil)); err != nil {
					return err
				}
				current.TypeValidated = true
				current.ObjectIssued = true
				v = current
				return tx.SaveVersion(current)
			})
			var object string
			if e == nil {
				object, e = s.ensureObject(ctx, v)
			}
			if e == nil {
				e = s.repo.Transaction(ctx, func(tx Transaction) error {
					f, current, err := s.load(tx, v.ID)
					if err != nil {
						return err
					}
					if terminal(current) || f.Disabled || f.Deleting || current.UploadGeneration != v.UploadGeneration {
						return ErrConflict
					}
					return s.authorize(ctx, p, "media.uploads.write", access(f, current, nil))
				})
			}
			if e == nil {
				_, ingestErr := s.store.Ingest(ctx, s.cfg.Actor, object, "media-ingest:"+v.ID, verifiedFile)
				e = storeError(ingestErr)
			}
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
		if current.UploadGeneration != v.UploadGeneration || terminal(current) {
			if terminal(current) {
				s.staging.remove(v.ID)
			}
			return nil
		}
		current.UploadUntil = time.Time{}
		current.Revision++
		switch {
		case e == nil:
			s.staging.remove(v.ID)
			current.State = "awaiting_approval"
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
			return s.emit(tx, p, "media.upload.checked", v.ID, current.Revision)
		case errors.Is(e, ErrIntegrity) || errors.Is(e, ErrType):
			s.staging.remove(v.ID)
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
			return s.emit(tx, p, "media.upload.checked", v.ID, current.Revision)
		case completedBytes && current.ObjectIssued:
			s.staging.remove(v.ID)
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
			return s.emit(tx, p, "media.upload.checked", v.ID, current.Revision)
		default:
			current.State = "uploading"
			current.UploadedBytes = s.staging.size(v.ID)
			out = current
			return tx.SaveVersion(current)
		}
	})
	if save != nil {
		return out, save
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
		err := s.repo.Transaction(ctx, func(tx Transaction) error {
			initial, ref, e := tx.Reference(id)
			if e != nil {
				return e
			}
			f, v, e := s.load(tx, initial.ID)
			if e != nil {
				return e
			}
			for _, r := range v.References {
				if r.ID == id {
					ref = r
				}
			}
			if e = s.authorize(ctx, p, "media.references.download", access(f, v, &ref)); e != nil {
				return e
			}
			if f.Disabled || f.Deleting || terminal(v) || !v.Approved || ref.State != "active" || v.ObjectID == "" {
				return ErrDenied
			}
			if object != "" && object != v.ObjectID {
				return ErrConflict
			}
			object = v.ObjectID
			expected = v.Profile.Published
			return nil
		})
		if err != nil {
			return err
		}
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
	check := func() error {
		e := s.repo.Transaction(ctx, func(tx Transaction) error {
			f, v, e := s.load(tx, id)
			if e != nil {
				return e
			}
			if e = s.authorize(ctx, p, "media.versions.review", access(f, v, nil)); e != nil {
				return e
			}
			if f.Disabled || f.Deleting || terminal(v) || (v.State != "awaiting_approval" && !v.Approved) || v.ObjectID == "" {
				return ErrDenied
			}
			if object != "" && object != v.ObjectID {
				return ErrConflict
			}
			object = v.ObjectID
			quarantine = v.Profile.Quarantine
			published = v.Profile.Published
			return nil
		})
		if e != nil {
			return e
		}
		status, e := s.store.Status(ctx, s.cfg.Actor, object)
		if e != nil {
			return storeError(e)
		}
		if status.Protection != quarantine && status.Protection != published {
			return ErrDenied
		}
		return nil
	}
	if e := check(); e != nil {
		return e
	}
	e = s.store.ReviewDownload(ctx, s.cfg.Actor, object, &checkedWriter{check: check, dst: dst})
	if errors.Is(e, ErrDenied) || errors.Is(e, ErrConflict) {
		return e
	}
	return storeError(e)
}
