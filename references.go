package media

import (
	"context"
	storage "github.com/StuHelper/stuhelper-storage"
)

func (s *Service) Attach(ctx context.Context, p Principal, id, key string, b Binding) (Reference, error) {
	var out Reference
	var v Version
	var f File
	if !idOK(b.Module) || !idOK(b.ResourceID) {
		return out, ErrInput
	}
	refID := hash([]string{id, b.Module, b.ResourceID})
	ref := Reference{ID: refID, VersionID: id, Module: b.Module, ResourceID: b.ResourceID, State: "pending", Revision: 1}
	e := s.mutation(ctx, p, "media.references.attach", id, key, b, func(tx Transaction) error {
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
		for _, r := range v.References {
			if r.ID == refID {
				if r.State == "released" {
					return nil, ErrConflict
				}
				return r, nil
			}
		}
		if len(v.References) >= s.cfg.MaxReferences {
			return nil, ErrCapacity
		}
		v.References = append(v.References, ref)
		if e := s.save(tx, p, v, "media.reference.attached"); e != nil {
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
	initial, _, e := tx.Reference(id)
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
	return f, v, Reference{}, ErrNotFound
}
func (s *Service) GetReference(ctx context.Context, p Principal, id string) (Reference, error) {
	var out Reference
	e := s.repo.Transaction(ctx, func(tx Transaction) error {
		f, v, r, e := s.reference(tx, id)
		if e != nil {
			return e
		}
		out = r
		return s.authorize(ctx, p, "media.references.read", access(f, v, &r))
	})
	return out, e
}
func (s *Service) ReferenceVersion(ctx context.Context, p Principal, id string) (Version, error) {
	var out Version
	e := s.repo.Transaction(ctx, func(tx Transaction) error {
		f, v, r, e := s.reference(tx, id)
		if e != nil {
			return e
		}
		out = v
		return s.authorize(ctx, p, "media.references.download", access(f, v, &r))
	})
	return out, e
}
func (s *Service) Release(ctx context.Context, p Principal, id, key string) (Reference, error) {
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
		if r.State == "released" {
			return r, nil
		}
		r.State = "released"
		r.Revision++
		for n := range v.References {
			if v.References[n].ID == id {
				v.References[n] = r
			}
		}
		if liveReferences(v) == 0 && !terminal(v) {
			v.State = "deleting"
		}
		if e := s.save(tx, p, v, "media.reference.released"); e != nil {
			return nil, e
		}
		return r, nil
	}, &out)
	return out, e
}
func (s *Service) Publish(ctx context.Context, p Principal, id, key string) (Reference, error) {
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
			if e := s.save(tx, p, v, "media.reference.publication_requested"); e != nil {
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
			return s.save(tx, p, v, "media.reference.published")
		}
		return nil
	})
	return r, e
}
