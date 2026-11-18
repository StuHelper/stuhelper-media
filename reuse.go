package media

import (
	"context"
	"errors"
	"reflect"
)

func (s *Service) reusable(f File, v Version, p Principal, request UploadRequest, profile Profile) bool {
	return f.Owner == p && !f.Disabled && !f.Deleting && !terminal(v) && v.TypeValidated && v.ObjectID != "" && (v.State == "awaiting_approval" || v.State == "approved" || v.State == "ready") && f.Purpose == request.Purpose && v.Size == request.Size && v.SHA256 == request.SHA256 && v.ContentType == request.ContentType && reflect.DeepEqual(v.Profile, profile) && (v.RetainUntil.After(s.now()) || activeReferences(v) > 0)
}

// Probe candidates without holding the owner or file mutation lock. The winner
// is checked again under its file lock when the new upload is committed.
func (s *Service) chooseReuse(ctx context.Context, p Principal, key string, r UploadRequest, profile Profile) (Version, error) {
	var candidates []Version
	err := s.repo.Transaction(ctx, func(tx Transaction) error {
		op := hash([]string{p.Issuer, p.Subject, "media.uploads.create", r.FileID, key})
		_, err := tx.Replay(op, s.now())
		if err == nil {
			return nil
		}
		if !errors.Is(err, ErrNotFound) {
			return err
		}
		candidates, err = tx.ReuseCandidates(p, r)
		return err
	})
	if err != nil {
		return Version{}, err
	}
	for _, v := range candidates {
		var f File
		err = s.repo.Transaction(ctx, func(tx Transaction) error { var err error; f, err = tx.File(v.FileID); return err })
		if err != nil {
			return Version{}, err
		}
		if !s.reusable(f, v, p, r, profile) {
			continue
		}
		if err = s.authorize(ctx, p, "media.files.read", access(f, v, nil)); errors.Is(err, ErrDenied) {
			continue
		} else if err != nil {
			return Version{}, err
		}
		st, err := s.store.Status(ctx, s.cfg.Actor, v.ObjectID)
		if err != nil {
			return Version{}, storeError(err)
		}
		if st.State != "deleted" && st.State != "deleting" && st.Healthy > 0 {
			return v, nil
		}
	}
	return Version{}, nil
}
func (s *Service) reuseUpload(ctx context.Context, p Principal, id string) (Version, error) {
	var v Version
	check := func(tx Transaction) error {
		if e := tx.Lock("owner:" + hash(p)); e != nil {
			return e
		}
		f, current, e := s.load(tx, id)
		if e != nil {
			return e
		}
		v = current
		if f.Owner != p {
			return ErrDenied
		}
		if f.Disabled || f.Deleting || terminal(current) {
			return ErrConflict
		}
		if e = s.authorize(ctx, p, "media.uploads.create", access(f, current, nil)); e != nil {
			return e
		}
		if current.State != "verifying" {
			return nil
		}
		if !current.Reused || current.ReuseSource == "" || !current.ExpiresAt.After(s.now()) {
			return ErrExpired
		}
		sourceFile, source, e := s.load(tx, current.ReuseSource)
		if e != nil {
			return e
		}
		request := UploadRequest{Purpose: f.Purpose, Size: current.Size, SHA256: current.SHA256, ContentType: current.ContentType}
		if !s.reusable(sourceFile, source, p, request, current.Profile) || source.ObjectID != current.ReuseObject {
			return ErrDenied
		}
		return s.authorize(ctx, p, "media.files.read", access(sourceFile, source, nil))
	}
	if e := s.repo.Transaction(ctx, check); e != nil {
		return v, e
	}
	if v.State != "verifying" {
		return v, nil
	}
	object, e := s.ensureObject(ctx, v)
	if e != nil {
		return v, e
	}
	st, e := s.store.Status(ctx, s.cfg.Actor, object)
	if e != nil {
		return v, storeError(e)
	}
	if st.Healthy < 1 {
		return v, ErrUnavailable
	}
	e = s.repo.Transaction(ctx, func(tx Transaction) error {
		if e := check(tx); e != nil {
			return e
		}
		if v.State != "verifying" {
			return nil
		}
		v.State = "awaiting_approval"
		v.UploadedBytes = v.Size
		v.ErrorCode = ""
		s.extendPendingRetention(&v)
		return s.save(ctx, tx, p, v, "media.upload.reused", nil)
	})
	if e != nil {
		return v, e
	}
	// Return the saved revision rather than the pre-save working value.
	e = s.repo.Transaction(ctx, func(tx Transaction) error { var e error; _, v, e = s.load(tx, id); return e })
	return v, e
}
