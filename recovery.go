package media

import (
	"context"
	"errors"
	"fmt"
	storage "github.com/StuHelper/stuhelper-storage"
	"time"
)

// Sweep only schedules bounded work. Persistent job claims coordinate instances.
func (s *Service) Sweep(ctx context.Context, n int, after string) (string, error) {
	if n < 1 || n > 100 || (after != "" && !idOK(after)) {
		return "", ErrInput
	}
	if e := s.authorize(ctx, s.cfg.Actor, "media.maintenance", Access{}); e != nil {
		return "", e
	}
	var rows []Version
	e := s.repo.Transaction(ctx, func(tx Transaction) error { var e error; rows, e = tx.ScanVersions(n, after); return e })
	if e != nil {
		return "", e
	}
	for _, entry := range rows {
		e = s.repo.Transaction(ctx, func(tx Transaction) error {
			f, v, e := s.load(tx, entry.ID)
			if e != nil {
				return e
			}
			if e = s.authorize(ctx, s.cfg.Actor, "media.maintenance", access(f, v, nil)); e != nil {
				return e
			}
			changed := false
			if !terminal(v) && activeReferences(v) == 0 && ((v.State == "created" || v.State == "uploading" || v.State == "verifying") && !v.ExpiresAt.After(s.now()) || !v.RetainUntil.After(s.now())) {
				v.State = "expired"
				v.ErrorCode = ErrExpired.Error()
				v.Revision++
				for k := range v.References {
					v.References[k].State = "released"
					v.References[k].Revision++
				}
				changed = true
			}
			if changed {
				if e = tx.SaveVersion(v); e != nil {
					return e
				}
				if e = s.emit(tx, s.cfg.Actor, "media.upload.expired", v.ID, v.Revision); e != nil {
					return e
				}
			}
			if v.CleanupComplete || v.State == "ready" || v.State == "created" {
				return nil
			}
			return s.schedule(tx, v.ID, false)
		})
		if e != nil {
			return "", e
		}
	}
	if len(rows) == n {
		return rows[len(rows)-1].ID, nil
	}
	return "", nil
}
func (s *Service) RunOne(ctx context.Context, worker string) (bool, error) {
	if !idOK(worker) {
		return false, ErrInput
	}
	if e := s.authorize(ctx, s.cfg.Actor, "media.maintenance", Access{}); e != nil {
		return false, e
	}
	ctx, done, e := s.begin(ctx)
	if e != nil {
		return false, e
	}
	defer done()
	j, e := s.repo.Claim(ctx, worker, s.now(), s.cfg.OperationTimeout+time.Second)
	if errors.Is(e, ErrNotFound) {
		return false, nil
	}
	if e != nil {
		return false, e
	}
	var f File
	var v Version
	e = s.repo.Transaction(ctx, func(tx Transaction) error {
		var e error
		f, v, e = s.load(tx, j.VersionID)
		if e != nil {
			return e
		}
		return s.authorize(ctx, s.cfg.Actor, "media.maintenance", access(f, v, nil))
	})
	initial := v.Revision
	waiting := false
	if e == nil {
		waiting, e = s.advance(ctx, j, f, v)
	}
	finish, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	saved := s.repo.Transaction(finish, func(tx Transaction) error {
		_, current, err := s.load(tx, j.VersionID)
		if err != nil {
			return err
		}
		now, err := tx.Job(j.VersionID)
		if err != nil {
			return err
		}
		if now.Generation != j.Generation || now.LeaseOwner != j.LeaseOwner || now.State != "running" || !now.LeaseUntil.After(s.now()) {
			return ErrConflict
		}
		now.LeaseOwner = ""
		now.LeaseUntil = time.Time{}
		if e != nil {
			now.Attempts++
			now.ErrorCode = errorCode(e)
			now.State = "pending"
			now.AvailableAt = s.now().Add(time.Duration(min(now.Attempts, 30)) * time.Second)
			if now.Attempts >= s.cfg.MaxAttempts || errors.Is(e, ErrDenied) {
				now.State = "blocked"
				if !terminal(current) {
					current.ErrorCode = now.ErrorCode
					if err = tx.SaveVersion(current); err != nil {
						return err
					}
				}
			}
		} else {
			now.Attempts = 0
			now.ErrorCode = ""
			now.State = "done"
			if waiting || current.Revision != initial {
				now.State = "pending"
				now.AvailableAt = s.now().Add(2 * time.Second)
			}
		}
		return tx.SaveJob(now)
	})
	if saved != nil {
		return true, saved
	}
	return true, e
}
func errorCode(e error) string {
	for _, known := range []error{ErrInput, ErrDenied, ErrConflict, ErrIntegrity, ErrType, ErrCapacity, ErrExpired} {
		if errors.Is(e, known) {
			return known.Error()
		}
	}
	return ErrUnavailable.Error()
}
func (s *Service) advance(ctx context.Context, j Job, f File, v Version) (bool, error) {
	if terminal(v) && !v.ObjectIssued {
		return false, s.cleanupDone(ctx, v.ID)
	}
	if v.UploadUntil.After(s.now()) {
		return true, nil
	}
	if !v.ObjectIssued {
		return false, nil
	}
	if v.Reused && !terminal(v) && v.State == "verifying" {
		_, e := s.reuseUpload(ctx, f.Owner, v.ID)
		return e == nil, e
	}
	id, e := s.ensureObject(ctx, v)
	if e != nil {
		return false, e
	}
	st, e := s.store.Status(ctx, s.cfg.Actor, id)
	if e != nil {
		return false, storeError(e)
	}
	if terminal(v) {
		if st.State == "deleted" {
			return false, s.cleanupDone(ctx, v.ID)
		}
		if st.State == "deleting" {
			return true, nil
		}
		// Each recovery attempt reconciles the constant media hold again. A late
		// attach from an older request cannot hide behind an earlier release replay.
		_, e = s.store.Reference(ctx, s.cfg.Actor, id, fmt.Sprintf("media-release:%s:%d", v.ID, j.Generation), storage.Reference{Module: "media", ID: v.ID}, false)
		if e != nil {
			return false, storeError(e)
		}
		st, e = s.store.Delete(ctx, s.cfg.Actor, id, fmt.Sprintf("media-delete:%s:%d", v.ID, st.Revision), st.Revision)
		if e != nil {
			return false, storeError(e)
		}
		if st.State == "deleted" {
			return false, s.cleanupDone(ctx, v.ID)
		}
		return true, nil
	}
	if f.Disabled {
		return false, nil
	}
	if st.State == "deleting" || st.State == "deleted" {
		return false, ErrConflict
	}
	if !v.TypeValidated {
		return false, ErrIntegrity
	}
	if st.Healthy < 1 {
		return true, nil
	}
	if v.State == "uploading" || v.State == "verifying" {
		e = s.updateObserved(ctx, v.ID, "awaiting_approval")
		return true, e
	}
	if !v.Approved {
		return false, nil
	}
	if st.Protection != v.Profile.Published {
		if st.Protection != v.Profile.Quarantine {
			return false, ErrConflict
		}
		st, e = s.store.ChangeProtection(ctx, s.cfg.Actor, id, fmt.Sprintf("media-promote:%s:%d", v.ID, st.Revision), st.Revision, v.Profile.Published)
		if e != nil {
			return false, storeError(e)
		}
	}
	if st.Healthy < st.Policy.Publish {
		return true, nil
	}
	return false, s.updateObserved(ctx, v.ID, "ready")
}
func (s *Service) updateObserved(ctx context.Context, id, state string) error {
	return s.repo.Transaction(ctx, func(tx Transaction) error {
		f, v, e := s.load(tx, id)
		if e != nil {
			return e
		}
		if terminal(v) || f.Disabled || f.Deleting {
			return nil
		}
		if state == "ready" && !v.Approved {
			return ErrConflict
		}
		if state == "awaiting_approval" && (v.Approved || v.State != "uploading" && v.State != "verifying") {
			return nil
		}
		if v.State == state {
			return nil
		}
		v.State = state
		v.ErrorCode = ""
		v.UploadUntil = time.Time{}
		v.Revision++
		if e = tx.SaveVersion(v); e != nil {
			return e
		}
		return s.emit(tx, s.cfg.Actor, "media.version."+state, v.ID, v.Revision)
	})
}
func (s *Service) cleanupDone(ctx context.Context, id string) error {
	return s.repo.Transaction(ctx, func(tx Transaction) error {
		_, v, e := s.load(tx, id)
		if e != nil {
			return e
		}
		if !terminal(v) {
			return ErrConflict
		}
		if v.CleanupComplete {
			return nil
		}
		v.CleanupComplete = true
		if v.State == "deleting" {
			v.State = "deleted"
		}
		v.Revision++
		if e = tx.SaveVersion(v); e != nil {
			return e
		}
		return s.emit(tx, s.cfg.Actor, "media.version.cleaned", v.ID, v.Revision)
	})
}
