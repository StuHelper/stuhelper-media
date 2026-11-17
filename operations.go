package media

import (
	"context"
	"errors"
	"strings"
	"time"
)

type traceContextKey struct{}

// WithTraceID attaches a sanitized printable ASCII trace identifier to ctx.
func WithTraceID(ctx context.Context, traceID string) context.Context {
	trimmed := strings.TrimSpace(traceID)
	if len(trimmed) == 0 || len(trimmed) > 128 {
		return ctx
	}
	for _, r := range trimmed {
		if r < 33 || r > 126 {
			return ctx
		}
	}
	return context.WithValue(ctx, traceContextKey{}, trimmed)
}

// TraceID returns the sanitized trace identifier attached to ctx, if any.
func TraceID(ctx context.Context) string {
	v, _ := ctx.Value(traceContextKey{}).(string)
	return v
}

func (s *Service) observe(ctx context.Context, operation string, started time.Time, err error) {
	if s.cfg.Observer == nil {
		return
	}
	code := ""
	if err != nil {
		code = errorCode(err)
	}
	s.cfg.Observer.Observe(ctx, Observation{
		Operation: operation,
		Duration:  max(time.Duration(0), s.now().Sub(started)),
		ErrorCode: code,
		TraceID:   TraceID(ctx),
	})
}

func jobFailure(j Job) JobFailure {
	return JobFailure{
		VersionID:   j.VersionID,
		State:       j.State,
		Generation:  j.Generation,
		Attempts:    j.Attempts,
		ErrorCode:   j.ErrorCode,
		AvailableAt: j.AvailableAt,
	}
}

func (s *Service) Operations(ctx context.Context, p Principal, limit int, failuresAfter string) (out Operations, err error) {
	started := s.now()
	defer func() { s.observe(ctx, "media.operations.read", started, err) }()

	out = Operations{
		GeneratedAt: started.UTC(),
		Failures:    []JobFailure{},
	}
	if limit < 1 || limit > 100 || (failuresAfter != "" && !idOK(failuresAfter)) {
		return out, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, s.cfg.OperationTimeout)
	defer cancel()
	if err = s.authorize(ctx, p, "media.maintenance", Access{}); err != nil {
		return out, err
	}
	err = s.repo.Transaction(ctx, func(tx Transaction) error {
		var e error
		now := s.now()
		out.Jobs, e = tx.JobTotals(now)
		if e != nil {
			return e
		}
		out.Outbox, e = tx.OutboxStatus(now)
		if e != nil {
			return e
		}
		jobs, e := tx.FailedJobs(limit, failuresAfter)
		if e != nil {
			return e
		}
		for _, j := range jobs {
			out.Failures = append(out.Failures, jobFailure(j))
		}
		if len(jobs) == limit {
			out.FailuresNextCursor = jobs[len(jobs)-1].VersionID
		}
		return s.authorize(ctx, p, "media.maintenance", Access{})
	})
	return out, err
}

func (s *Service) RetryJob(ctx context.Context, p Principal, versionID, key string, generation int64) (out JobFailure, err error) {
	started := s.now()
	defer func() { s.observe(ctx, "media.jobs.retry", started, err) }()

	if !idOK(versionID) || generation < 1 {
		return out, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, s.cfg.OperationTimeout)
	defer cancel()
	var f File
	var v Version
	err = s.mutation(ctx, p, "media.jobs.retry", versionID, key, RetryJobRequest{Generation: generation}, func(tx Transaction) error {
		var e error
		f, v, e = s.load(tx, versionID)
		if e != nil {
			return e
		}
		return s.authorize(ctx, p, "media.maintenance", access(f, v, nil))
	}, func(tx Transaction) (any, error) {
		if v.CleanupComplete || v.State == "ready" {
			return nil, ErrConflict
		}
		j, e := tx.Job(versionID)
		if e != nil {
			return nil, e
		}
		if j.State != "blocked" || j.Generation != generation {
			return nil, ErrConflict
		}
		j.Generation++
		j.State = "pending"
		j.Attempts = 0
		j.ErrorCode = ""
		j.LeaseOwner = ""
		j.LeaseUntil = time.Time{}
		j.AvailableAt = s.now()
		if e = tx.SaveJob(j); e != nil {
			return nil, e
		}
		if e = s.emit(tx, p, "media.job.retried", v.ID, v.Revision); e != nil {
			return nil, e
		}
		return jobFailure(j), nil
	}, &out)
	return out, err
}

func (s *Service) Prune(ctx context.Context, limit int) (PruneResult, error) {
	return s.PruneAs(ctx, s.cfg.Actor, limit)
}

func (s *Service) PruneAs(ctx context.Context, p Principal, limit int) (out PruneResult, err error) {
	started := s.now()
	defer func() { s.observe(ctx, "media.operations.prune", started, err) }()

	if limit < 1 || limit > 1000 {
		return out, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, s.cfg.OperationTimeout)
	defer cancel()
	if err = s.authorize(ctx, p, "media.maintenance", Access{}); err != nil {
		return out, err
	}
	cutoff := s.now().Add(-s.cfg.HistoryRetention)
	err = s.repo.Transaction(ctx, func(tx Transaction) error {
		if e := s.authorize(ctx, p, "media.maintenance", Access{}); e != nil {
			return e
		}
		var e error
		out, e = tx.PruneHistory(cutoff, limit)
		return e
	})
	return out, err
}

func (s *Service) Readiness(ctx context.Context) (err error) {
	started := s.now()
	defer func() { s.observe(ctx, "media.readiness", started, err) }()

	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed || s.ctx.Err() != nil {
		return ErrUnavailable
	}
	timeout := min(s.cfg.OperationTimeout, 5*time.Second)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err = s.authorize(ctx, s.cfg.Actor, "media.maintenance", Access{}); err != nil {
		return err
	}
	if err = s.repo.Transaction(ctx, func(Transaction) error { return nil }); err != nil {
		return err
	}
	_, storeErr := s.store.Status(ctx, s.cfg.Actor, "media-readiness-probe")
	mapped := storeError(storeErr)
	if mapped != nil && !errors.Is(mapped, ErrNotFound) {
		return mapped
	}
	return nil
}
