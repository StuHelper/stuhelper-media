package media

import (
	"context"
	"errors"
	storage "github.com/StuHelper/stuhelper-storage"
	"slices"
)

func (s *Service) Attach(ctx context.Context, p Principal, id, key string, b Binding) (Reference, error) {
	return s.attach(ctx, p, id, key, b, false)
}

// AttachPublication creates the binding for one publication attempt. Retrying
// that operation reuses the binding. Restoring content starts a new operation.
func (s *Service) AttachPublication(ctx context.Context, p Principal, id, key string, b Binding) (Reference, error) {
	return s.attach(ctx, p, id, key, b, true)
}

func (s *Service) attach(ctx context.Context, p Principal, id, key string, b Binding, publication bool) (Reference, error) {
	ctx, finish, startErr := s.operation(ctx)
	if startErr != nil {
		return Reference{}, startErr
	}
	defer finish()
	var out Reference
	var v Version
	var f File
	if !idOK(b.Module) || !idOK(b.ResourceID) {
		return out, ErrInput
	}
	refID := hash([]string{id, b.Module, b.ResourceID})
	var request any = b
	if publication {
		refID = PublicationReferenceID(id, b, key)
		request = struct {
			Binding
			Publication bool
		}{b, true}
	}
	ref := Reference{ID: refID, VersionID: id, Module: b.Module, ResourceID: b.ResourceID, State: "pending", Revision: 1}
	e := s.mutation(ctx, p, "media.references.attach", id, key, request, func(tx Transaction) error {
		var e error
		f, v, e = s.load(tx, id)
		if e != nil {
			return e
		}
		ref.FileID = f.ID
		if b.Module != v.Profile.Module {
			return ErrDenied
		}
		return s.authorize(ctx, p, "media.references.attach", access(f, v, &ref))
	}, func(tx Transaction) (any, error) {
		if f.Disabled || f.Deleting || terminal(v) {
			return nil, ErrConflict
		}
		_, existing, err := tx.Reference(refID)
		if err == nil {
			if existing.State == "released" {
				return nil, ErrConflict
			}
			return existing, nil
		}
		if !errors.Is(err, ErrNotFound) {
			return nil, err
		}
		if liveReferences(v) >= s.cfg.MaxReferences {
			return nil, withLimit(ErrReferenceLimit, int64(s.cfg.MaxReferences))
		}
		// Released bindings stay addressable in media.references. Keep only live
		// bindings in the version snapshot used by subsequent writes.
		v.References = slices.DeleteFunc(v.References, func(r Reference) bool { return r.State == "released" })
		v.References = append(v.References, ref)
		s.extendPendingRetention(&v)
		if e := s.save(ctx, tx, p, v, "media.reference.attached", &ref); e != nil {
			return nil, e
		}
		return ref, nil
	}, &out)
	return out, e
}
func (s *Service) reference(tx Transaction, id string) (File, Version, Reference, error) {
	if !idOK(id) {
		return File{}, Version{}, Reference{}, ErrInput
	}
	initial, history, e := tx.Reference(id)
	if e != nil {
		return File{}, Version{}, Reference{}, e
	}
	f, v, e := s.load(tx, initial.ID)
	if e != nil {
		return f, v, Reference{}, e
	}
	for _, r := range v.References {
		if r.ID == id {
			return f, v, r, nil
		}
	}
	if history.State == "released" {
		return f, v, history, nil
	}
	_, latest, e := tx.Reference(id)
	return f, v, latest, e
}
func (s *Service) GetReference(ctx context.Context, p Principal, id string) (Reference, error) {
	ctx, finish, startErr := s.operation(ctx)
	if startErr != nil {
		return Reference{}, startErr
	}
	defer finish()
	row, e := s.readReference(ctx, id)
	if e != nil {
		return Reference{}, e
	}
	e = s.authorize(ctx, p, "media.references.read", access(row.File, row.Version, &row.Reference))
	if e != nil {
		return Reference{}, e
	}
	return row.Reference, nil
}
func (s *Service) readReference(ctx context.Context, id string) (ReferenceSnapshot, error) {
	if !idOK(id) {
		return ReferenceSnapshot{}, ErrInput
	}
	var rows map[string]ReferenceSnapshot
	e := s.repo.Transaction(ctx, func(tx Transaction) error { var err error; rows, err = tx.ReadReferences([]string{id}); return err })
	if e != nil {
		return ReferenceSnapshot{}, e
	}
	row, ok := rows[id]
	if !ok {
		return row, ErrNotFound
	}
	return row, nil
}
func (s *Service) downloadVersion(ctx context.Context, p Principal, row ReferenceSnapshot) (Version, error) {
	f, v, r := row.File, row.Version, row.Reference
	if e := s.authorize(ctx, p, "media.references.download", access(f, v, &r)); e != nil {
		return Version{}, e
	}
	if f.Disabled || f.Deleting || terminal(v) || !v.Approved || r.State != "active" || v.ObjectID == "" {
		return Version{}, ErrDenied
	}
	return v, nil
}
func (s *Service) ReferenceVersion(ctx context.Context, p Principal, id string) (Version, error) {
	ctx, finish, startErr := s.operation(ctx)
	if startErr != nil {
		return Version{}, startErr
	}
	defer finish()
	row, e := s.readReference(ctx, id)
	if e != nil {
		return Version{}, e
	}
	return s.downloadVersion(ctx, p, row)
}
func (s *Service) InspectReferenceDownload(ctx context.Context, p Principal, id string) (Version, error) {
	ctx, done, err := s.operation(ctx)
	if err != nil {
		return Version{}, err
	}
	defer done()
	row, e := s.readReference(ctx, id)
	if e != nil {
		return Version{}, e
	}
	v, e := s.downloadVersion(ctx, p, row)
	if e != nil {
		return Version{}, e
	}
	st, e := s.store.Status(ctx, s.cfg.Actor, v.ObjectID)
	if e != nil {
		return Version{}, storeError(e)
	}
	if st.Protection != v.Profile.Published {
		return Version{}, ErrDenied
	}
	if st.Healthy < 1 {
		return Version{}, ErrUnavailable
	}
	return v, nil
}
func (s *Service) Release(ctx context.Context, p Principal, id, key string) (Reference, error) {
	ctx, finish, startErr := s.operation(ctx)
	if startErr != nil {
		return Reference{}, startErr
	}
	defer finish()
	var out, r Reference
	var f File
	var v Version
	e := s.mutation(ctx, p, "media.references.release", id, key, struct{}{}, func(tx Transaction) error {
		var e error
		f, v, r, e = s.reference(tx, id)
		if e != nil {
			return e
		}
		return s.authorize(ctx, p, "media.references.release", access(f, v, &r))
	}, func(tx Transaction) (any, error) {
		return s.releaseBinding(ctx, tx, p, v, r)
	}, &out)
	return out, e
}

// RetirePublication also handles a lost attach response. Loading the version
// first serializes retirement with any attach still writing this binding.
func (s *Service) RetirePublication(ctx context.Context, p Principal, versionID, key string, b Binding, publicationKey string) error {
	if !idOK(versionID) || !idOK(b.Module) || !idOK(b.ResourceID) || !validKey(publicationKey) {
		return ErrInput
	}
	ctx, finish, err := s.operation(ctx)
	if err != nil {
		return err
	}
	defer finish()
	id := PublicationReferenceID(versionID, b, publicationKey)
	var v Version
	var ref Reference
	var found bool
	var out Reference
	return s.mutation(ctx, p, "media.references.release", id, key, b, func(tx Transaction) error {
		f, version, err := s.load(tx, versionID)
		if err != nil {
			return err
		}
		v = version
		_, ref, err = tx.Reference(id)
		found = err == nil
		if errors.Is(err, ErrNotFound) {
			ref = Reference{ID: id, VersionID: versionID, FileID: f.ID, Module: b.Module, ResourceID: b.ResourceID}
		} else if err != nil {
			return err
		}
		return s.authorize(ctx, p, "media.references.release", access(f, v, &ref))
	}, func(tx Transaction) (any, error) {
		if !found {
			return ref, nil
		}
		return s.releaseBinding(ctx, tx, p, v, ref)
	}, &out)
}
func (s *Service) releaseBinding(ctx context.Context, tx Transaction, p Principal, v Version, r Reference) (any, error) {
	if r.State == "released" {
		return r, nil
	}
	r.State = "released"
	r.Revision++
	for n := range v.References {
		if v.References[n].ID == r.ID {
			v.References[n] = r
		}
	}
	if liveReferences(v) == 0 && !terminal(v) {
		keep, err := s.retainSource(ctx, v)
		if err != nil {
			return nil, err
		}
		if !keep {
			v.State = "deleting"
		}
	}
	if e := s.save(ctx, tx, p, v, "media.reference.released", &r); e != nil {
		return nil, e
	}
	return r, nil
}
func (s *Service) Publish(ctx context.Context, p Principal, id, key string) (Reference, error) {
	ctx, finish, startErr := s.operation(ctx)
	if startErr != nil {
		return Reference{}, startErr
	}
	defer finish()
	var intent, r Reference
	var f File
	var v Version
	e := s.mutation(ctx, p, "media.references.publish", id, key, struct{}{}, func(tx Transaction) error {
		var e error
		f, v, r, e = s.reference(tx, id)
		if e != nil {
			return e
		}
		return s.authorize(ctx, p, "media.references.publish", access(f, v, &r))
	}, func(tx Transaction) (any, error) {
		if f.Disabled || f.Deleting || terminal(v) || !v.Approved || r.State == "released" {
			return nil, ErrConflict
		}
		if r.State == "pending" {
			r.State = "publishing"
			r.Revision++
			for n := range v.References {
				if v.References[n].ID == id {
					v.References[n] = r
				}
			}
			if e := s.save(ctx, tx, p, v, "media.reference.publication_requested", &r); e != nil {
				return nil, e
			}
		}
		return r, nil
	}, &intent)
	if e != nil {
		return intent, e
	}
	// Recovery needs a fresh authorized request. A durable intent alone does not
	// prove that the owning business still approves publication.
	e = s.repo.Transaction(ctx, func(tx Transaction) error {
		var e error
		f, v, r, e = s.reference(tx, id)
		if e != nil {
			return e
		}
		if e = s.authorize(ctx, p, "media.references.publish", access(f, v, &r)); e != nil {
			return e
		}
		if f.Disabled || f.Deleting || terminal(v) || r.State == "released" {
			return ErrConflict
		}
		return nil
	})
	if e != nil || r.State == "active" {
		return r, e
	}
	if v.ObjectID == "" {
		return r, ErrUnavailable
	}
	st, e := s.store.Status(ctx, s.cfg.Actor, v.ObjectID)
	if e != nil {
		return r, storeError(e)
	}
	if st.Protection != v.Profile.Published || st.Healthy < st.Policy.Publish {
		return r, ErrUnavailable
	}
	_, e = s.store.Reference(ctx, s.cfg.Actor, v.ObjectID, "media-publish:"+v.ID, storage.Reference{Module: "media", ID: v.ID}, true)
	if e != nil {
		return r, storeError(e)
	}
	e = s.repo.Transaction(ctx, func(tx Transaction) error {
		f, v, current, e := s.reference(tx, id)
		if e != nil {
			return e
		}
		r = current
		if e = s.authorize(ctx, p, "media.references.publish", access(f, v, &r)); e != nil {
			return e
		}
		if f.Disabled || f.Deleting || terminal(v) || r.State == "released" {
			return ErrConflict
		}
		if r.State != "active" {
			r.State = "active"
			r.Revision++
			for n := range v.References {
				if v.References[n].ID == id {
					v.References[n] = r
				}
			}
			return s.save(ctx, tx, p, v, "media.reference.published", &r)
		}
		return nil
	})
	return r, e
}
