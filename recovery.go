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
	ctx, finish, startErr := s.operation(ctx)
	if startErr != nil {
		return "", startErr
	}
	defer finish()
	if n < 1 || n > 100 || (after != "" && !idOK(after)) {
		return "", ErrInput
	}
	if e := s.authorize(ctx, s.cfg.Actor, "media.maintenance", Access{}); e != nil {
		return "", e
	}
	var rows []Version
	e := s.repo.Transaction(ctx, func(tx Transaction) error {
		if err := tx.PruneReplays(s.now(), n); err != nil {
			return err
		}
		var e error
		rows, e = tx.ScanVersions(n, after)
		return e
	})
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
			activeUpload := v.State == "uploading" && v.UploadUntil.After(s.now())
			if !terminal(v) && !activeUpload && activeReferences(v) == 0 && ((v.State == "created" || v.State == "uploading" || v.State == "verifying") && !v.ExpiresAt.After(s.now()) || !v.RetainUntil.After(s.now())) {
				keep, err := s.retainSource(ctx, v)
				if err != nil {
					return err
				}
				if keep {
					return nil
				}
				v.State = "expired"
				v.UploadedBytes = 0
				v.ErrorCode = ErrExpired.Error()
				v.UploadUntil = time.Time{}
				v.UploadGeneration++
				if err := s.releaseBindings(ctx, tx, s.cfg.Actor, &v); err != nil {
					return err
				}
				v.Revision++
				changed = true
			}
			if changed {
				s.staging.remove(v.ID)
				if e = tx.SaveVersion(v); e != nil {
					return e
				}
				if e = s.emit(ctx, tx, s.cfg.Actor, "media.upload.expired", v.ID, v.Revision, v.Profile.SchoolID, nil); e != nil {
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
func (s *Service) RunOne(ctx context.Context, worker string) (ran bool, retErr error) {
	started := s.now()
	defer func() { s.observe(ctx, "media.jobs.run", started, retErr) }()
	if !idOK(worker) {
		return false, ErrInput
	}
	ctx, done, e := s.begin(ctx)
	if e != nil {
		return false, e
	}
	defer done()
	if e := s.authorize(ctx, s.cfg.Actor, "media.maintenance", Access{}); e != nil {
		return false, e
	}
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
			now.AvailableAt = s.now().Add(min(5*time.Second<<min(now.Attempts-1, 6), 5*time.Minute))
			if now.Attempts >= s.cfg.MaxAttempts || errors.Is(e, ErrDenied) {
				now.State = "blocked"
				current.ErrorCode = now.ErrorCode
				current.Revision++
				if err = tx.SaveVersion(current); err != nil {
					return err
				}
				if err = s.emit(finish, tx, s.cfg.Actor, "media.job.blocked", current.ID, current.Revision, current.Profile.SchoolID, nil); err != nil {
					return err
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
	for _, known := range []error{
		ErrTransferBusy, ErrOpenUploadsLimit, ErrFileLimit, ErrVersionLimit, ErrReferenceLimit, ErrArchiveTooLarge,
		ErrUploadTooLarge, ErrFilenameInvalid, ErrTypeNotAllowed,
		ErrInput, ErrDenied, ErrConflict, ErrIntegrity, ErrType, ErrCapacity, ErrExpired,
	} {
		if errors.Is(e, known) {
			return known.Error()
		}
	}
	return ErrUnavailable.Error()
}
func (s *Service) advance(ctx context.Context, j Job, f File, v Version) (bool, error) {
	if terminal(v) {
		var allowed bool
		err := s.repo.Transaction(ctx, func(tx Transaction) error { var e error; allowed, e = tx.BeginVersionCleanup(v.ID); return e })
		if err != nil || !allowed {
			return true, err
		}
	}
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
	if v.Prepared && !v.TypeValidated {
		return false, nil
	}
	if !v.TypeValidated {
		return false, ErrIntegrity
	}
	if st.Healthy < 1 {
		return true, nil
	}
	if v.State == "uploading" || v.State == "verifying" {
		e = s.updateObserved(ctx, v, "awaiting_approval")
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
	if !st.CanReference() {
		return true, nil
	}
	return false, s.updateObserved(ctx, v, "ready")
}
func (s *Service) updateObserved(ctx context.Context, observed Version, state string) error {
	return s.repo.Transaction(ctx, func(tx Transaction) error {
		f, v, e := s.load(tx, observed.ID)
		if e != nil {
			return e
		}
		if v.UploadGeneration != observed.UploadGeneration || v.UploadUntil.After(s.now()) {
			return ErrConflict
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
		v.UploadedBytes = v.Size
		v.ErrorCode = ""
		v.UploadUntil = time.Time{}
		v.UploadGeneration++
		s.extendPendingRetention(&v)
		v.Revision++
		s.staging.remove(v.ID)
		if e = tx.SaveVersion(v); e != nil {
			return e
		}
		return s.emit(ctx, tx, s.cfg.Actor, "media.version."+state, v.ID, v.Revision, v.Profile.SchoolID, nil)
	})
}
func (s *Service) cleanupDone(ctx context.Context, id string) error {
	return s.repo.Transaction(ctx, func(tx Transaction) error {
		f, v, e := s.load(tx, id)
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
		v.UploadedBytes = 0
		if v.State == "deleting" {
			v.State = "deleted"
		}
		v.Revision++
		s.staging.remove(v.ID)
		if e = tx.SaveVersion(v); e != nil {
			return e
		}
		versions, e := tx.Versions(f.ID)
		if e != nil {
			return e
		}
		allClean := true
		for _, version := range versions {
			if !version.CleanupComplete {
				allClean = false
				break
			}
		}
		if allClean && !f.Retired {
			f.Retired = true
			f.Disabled = true
			f.Deleting = false
			f.Revision++
			if e = tx.SaveFile(f); e != nil {
				return e
			}
		}
		return s.emit(ctx, tx, s.cfg.Actor, "media.version.cleaned", v.ID, v.Revision, v.Profile.SchoolID, nil)
	})
}
