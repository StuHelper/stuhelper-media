// Package postgres owns media metadata and migrations, using a separate role.
package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	media "github.com/StuHelper/stuhelper-media"
	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
	"time"
)

//go:embed schema.sql
var Schema string

type Repository struct{ DB *sql.DB }
type transaction struct {
	tx  *sql.Tx
	ctx context.Context
}
type fileRecord struct {
	media.File
	Owner       media.Principal `json:"owner"`
	NextVersion int             `json:"next_version"`
}
type versionRecord struct {
	media.Version
	ObjectID         string            `json:"object_id"`
	ObjectIssued     bool              `json:"object_issued"`
	TypeValidated    bool              `json:"type_validated"`
	UploadGeneration int64             `json:"upload_generation"`
	UploadUntil      time.Time         `json:"upload_until"`
	Profile          media.Profile     `json:"profile"`
	References       []media.Reference `json:"references"`
}

func record(v media.Version) versionRecord {
	return versionRecord{v, v.ObjectID, v.ObjectIssued, v.TypeValidated, v.UploadGeneration, v.UploadUntil, v.Profile, v.References}
}
func (r versionRecord) value() media.Version {
	v := r.Version
	v.ObjectID = r.ObjectID
	v.ObjectIssued = r.ObjectIssued
	v.TypeValidated = r.TypeValidated
	v.UploadGeneration = r.UploadGeneration
	v.UploadUntil = r.UploadUntil
	v.Profile = r.Profile
	v.References = r.References
	return v
}
func safe(e error) error {
	if e == nil {
		return nil
	}
	if errors.Is(e, sql.ErrNoRows) {
		return media.ErrNotFound
	}
	if errors.Is(e, context.Canceled) || errors.Is(e, context.DeadlineExceeded) {
		return e
	}
	var pg *pgconn.PgError
	if errors.As(e, &pg) && (pg.Code == "23505" || pg.Code == "40001" || pg.Code == "40P01") {
		return media.ErrConflict
	}
	return media.ErrUnavailable
}
func (r *Repository) Transaction(ctx context.Context, run func(media.Transaction) error) error {
	tx, e := r.DB.BeginTx(ctx, nil)
	if e != nil {
		return safe(e)
	}
	defer tx.Rollback()
	if e = run(&transaction{tx, ctx}); e != nil {
		return e
	}
	return safe(tx.Commit())
}
func (t *transaction) Lock(key string) error {
	_, e := t.tx.ExecContext(t.ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "stuhelper-media:"+key)
	return safe(e)
}
func read[T any](t *transaction, q string, args ...any) (T, error) {
	var v T
	var b []byte
	e := t.tx.QueryRowContext(t.ctx, q, args...).Scan(&b)
	if e != nil {
		return v, safe(e)
	}
	if json.Unmarshal(b, &v) != nil {
		return v, media.ErrUnavailable
	}
	return v, nil
}
func list[T any](t *transaction, q string, args ...any) ([]T, error) {
	rows, e := t.tx.QueryContext(t.ctx, q, args...)
	if e != nil {
		return nil, safe(e)
	}
	defer rows.Close()
	out := []T{}
	for rows.Next() {
		var b []byte
		var v T
		if rows.Scan(&b) != nil || json.Unmarshal(b, &v) != nil {
			return nil, media.ErrUnavailable
		}
		out = append(out, v)
	}
	return out, safe(rows.Err())
}
func (t *transaction) save(q string, v any, args ...any) error {
	b, e := json.Marshal(v)
	if e != nil {
		return media.ErrInput
	}
	args = append(args, string(b))
	_, e = t.tx.ExecContext(t.ctx, q, args...)
	return safe(e)
}
func owner(p media.Principal) string {
	b, _ := json.Marshal(p)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func (t *transaction) File(id string) (media.File, error) {
	r, e := read[fileRecord](t, `SELECT data FROM media.files WHERE id=$1`, id)
	r.File.Owner = r.Owner
	r.File.NextVersion = r.NextVersion
	return r.File, e
}
func (t *transaction) SaveFile(v media.File) error {
	return t.save(`INSERT INTO media.files(id,owner_key,data) VALUES($1,$2,$3) ON CONFLICT(id) DO UPDATE SET data=excluded.data`, fileRecord{v, v.Owner, v.NextVersion}, v.ID, owner(v.Owner))
}
func (t *transaction) Version(id string) (media.Version, error) {
	v, e := read[versionRecord](t, `SELECT data FROM media.versions WHERE id=$1`, id)
	return v.value(), e
}
func (t *transaction) Upload(id string) (media.Version, error) {
	v, e := read[versionRecord](t, `SELECT data FROM media.versions WHERE upload_id=$1`, id)
	return v.value(), e
}
func (t *transaction) Reference(id string) (media.Version, media.Reference, error) {
	ref, e := read[media.Reference](t, `SELECT data FROM media.references WHERE id=$1`, id)
	if e != nil {
		return media.Version{}, ref, e
	}
	v, e := t.Version(ref.VersionID)
	return v, ref, e
}
func (t *transaction) Versions(id string) ([]media.Version, error) {
	vs, e := list[versionRecord](t, `SELECT data FROM media.versions WHERE file_id=$1 ORDER BY number LIMIT 101`, id)
	out := []media.Version{}
	for _, v := range vs {
		out = append(out, v.value())
	}
	return out, e
}
func (t *transaction) ScanVersions(n int, after string) ([]media.Version, error) {
	vs, e := list[versionRecord](t, `SELECT data FROM media.versions WHERE id>$1 ORDER BY id LIMIT $2`, after, n)
	out := []media.Version{}
	for _, v := range vs {
		out = append(out, v.value())
	}
	return out, e
}
func (t *transaction) SaveVersion(v media.Version) error {
	if e := t.save(`INSERT INTO media.versions(id,file_id,upload_id,number,state,data) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(id) DO UPDATE SET state=excluded.state,data=excluded.data`, record(v), v.ID, v.FileID, v.UploadID, v.Number, v.State); e != nil {
		return e
	}
	for _, r := range v.References {
		if e := t.save(`INSERT INTO media.references(id,version_id,data) VALUES($1,$2,$3) ON CONFLICT(id) DO UPDATE SET data=excluded.data`, r, r.ID, r.VersionID); e != nil {
			return e
		}
	}
	return nil
}
func (t *transaction) Counts(p media.Principal) (files, open int, err error) {
	err = t.tx.QueryRowContext(t.ctx, `SELECT (SELECT count(*) FROM media.files WHERE owner_key=$1),(SELECT count(*) FROM media.versions v JOIN media.files f ON f.id=v.file_id WHERE f.owner_key=$1 AND v.state IN ('created','uploading','verifying'))`, owner(p)).Scan(&files, &open)
	return files, open, safe(err)
}
func (t *transaction) Replay(k string) (media.Replay, error) {
	return read[media.Replay](t, `SELECT data FROM media.replays WHERE key=$1`, k)
}
func (t *transaction) SaveReplay(v media.Replay) error {
	return t.save(`INSERT INTO media.replays(key,data) VALUES($1,$2)`, v, v.Key)
}
func (t *transaction) Job(id string) (media.Job, error) {
	return read[media.Job](t, `SELECT data FROM media.jobs WHERE version_id=$1 FOR UPDATE`, id)
}
func (t *transaction) SaveJob(j media.Job) error {
	return t.save(`INSERT INTO media.jobs(version_id,state,available_at,lease_until,data) VALUES($1,$2,$3,$4,$5) ON CONFLICT(version_id) DO UPDATE SET state=excluded.state,available_at=excluded.available_at,lease_until=excluded.lease_until,data=excluded.data`, j, j.VersionID, j.State, j.AvailableAt, j.LeaseUntil)
}
func (t *transaction) Event(e media.Event) error {
	e.SpecVersion = "1.0"
	e.Source = "stuhelper://media"
	e.DataContentType = "application/json"
	e.Data = media.EventData{Revision: e.Revision}
	if err := t.save(`INSERT INTO media.outbox(id,data) VALUES($1,$2)`, e, e.ID); err != nil {
		return err
	}
	return t.save(`INSERT INTO media.audit(id,data) VALUES($1,$2)`, struct {
		Event media.Event     `json:"event"`
		Actor media.Principal `json:"actor"`
	}{e, e.Actor}, e.ID)
}
func (r *Repository) Claim(ctx context.Context, worker string, now time.Time, lease time.Duration) (media.Job, error) {
	var out media.Job
	e := r.Transaction(ctx, func(tx media.Transaction) error {
		t := tx.(*transaction)
		j, e := read[media.Job](t, `SELECT data FROM media.jobs WHERE (state='pending' AND available_at<=$1) OR (state='running' AND lease_until<=$1) ORDER BY available_at,version_id FOR UPDATE SKIP LOCKED LIMIT 1`, now)
		if e != nil {
			return e
		}
		j.Generation++
		j.LeaseOwner = worker
		j.LeaseUntil = now.Add(lease)
		j.State = "running"
		out = j
		return tx.SaveJob(j)
	})
	return out, e
}
func (r *Repository) PendingEvents(ctx context.Context, n int) ([]media.Event, error) {
	if n < 1 || n > 100 {
		return nil, media.ErrInput
	}
	var out []media.Event
	e := r.Transaction(ctx, func(tx media.Transaction) error {
		var e error
		out, e = list[media.Event](tx.(*transaction), `SELECT data FROM media.outbox WHERE NOT delivered ORDER BY id LIMIT $1`, n)
		return e
	})
	return out, e
}
func (r *Repository) AcknowledgeEvent(ctx context.Context, id string) error {
	_, e := r.DB.ExecContext(ctx, `UPDATE media.outbox SET delivered=true WHERE id=$1`, id)
	return safe(e)
}
func (r *Repository) CheckRuntime(ctx context.Context) error {
	var super, createDB, createRole, ownerSchema, storageAccess bool
	e := r.DB.QueryRowContext(ctx, `SELECT rolsuper,rolcreatedb,rolcreaterole,(SELECT nspowner=(SELECT oid FROM pg_roles WHERE rolname=current_user) FROM pg_namespace WHERE nspname='media'),COALESCE((SELECT has_schema_privilege(current_user,oid,'USAGE') FROM pg_namespace WHERE nspname='storage'),false) FROM pg_roles WHERE rolname=current_user`).Scan(&super, &createDB, &createRole, &ownerSchema, &storageAccess)
	if e != nil || super || createDB || createRole || ownerSchema || storageAccess {
		return media.ErrDenied
	}
	var readAudit, writeAudit, changeAudit bool
	e = r.DB.QueryRowContext(ctx, `SELECT has_table_privilege('media.audit','SELECT'),has_table_privilege('media.audit','INSERT'),has_table_privilege('media.audit','UPDATE,DELETE')`).Scan(&readAudit, &writeAudit, &changeAudit)
	if e != nil || !readAudit || !writeAudit || changeAudit {
		return media.ErrDenied
	}
	return nil
}
