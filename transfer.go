package media

import (
	"bytes"
	"context"
	"errors"
	storage "github.com/StuHelper/stuhelper-storage"
	"io"
	"mime"
	"net/http"
	"time"
)

func (s *Service) ensureObject(ctx context.Context, v Version) (string, error) {
	if v.ObjectID != "" {
		return v.ObjectID, nil
	}
	if !v.ObjectIssued {
		return "", ErrConflict
	}
	st, e := s.store.Create(ctx, s.cfg.Actor, "media-create:"+v.ID, storage.CreateRequest{ClientKey: "media:" + v.ID, Size: v.Size, SHA256: v.SHA256, Protection: v.Profile.Quarantine})
	if e != nil {
		return "", storeError(e)
	}
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
	return st.ID, e
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
			complete = true
			return nil
		}
		if !v.ExpiresAt.After(s.now()) {
			return ErrExpired
		}
		if v.UploadUntil.After(s.now()) {
			return ErrConflict
		}
		v.State = "uploading"
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
			current.ErrorCode = ""
		case errors.Is(e, ErrIntegrity) || errors.Is(e, ErrType):
			current.State = "rejected"
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
	if e = check(); e != nil {
		return e
	}
	e = s.store.Download(ctx, s.cfg.Actor, object, &checkedWriter{check: check, dst: dst})
	// A business denial from the final writer is already a media error.
	if errors.Is(e, ErrDenied) || errors.Is(e, ErrConflict) {
		return e
	}
	return storeError(e)
}
