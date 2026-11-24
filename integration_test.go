package media_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	media "github.com/StuHelper/stuhelper-media"
	mp "github.com/StuHelper/stuhelper-media/postgres"
	storage "github.com/StuHelper/stuhelper-storage"
	sp "github.com/StuHelper/stuhelper-storage/postgres"
	"github.com/StuHelper/stuhelper-storage/storagetest"
	"github.com/jackc/pgx/v5/stdlib"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var user = media.Principal{Issuer: "urn:fixture", Subject: "owner"}
var system = media.Principal{Issuer: "urn:fixture:media", Subject: "service"}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

type policy struct {
	mu     sync.Mutex
	denied map[string]bool
}

func (p *policy) Authorize(_ context.Context, actor media.Principal, action string, a media.Access) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.denied[action] || actor != user && actor != system {
		return media.ErrDenied
	}
	if action == "media.maintenance" {
		if actor != system {
			return media.ErrDenied
		}
		return nil
	}
	if actor != user || a.Owner != user {
		return media.ErrDenied
	}
	if a.Reference != nil && (a.Reference.Module != "fixture" || strings.HasPrefix(a.Reference.ResourceID, "foreign")) {
		return media.ErrDenied
	}
	return nil
}
func (p *policy) deny(action string, on bool) { p.mu.Lock(); p.denied[action] = on; p.mu.Unlock() }

type storagePolicy struct{}

func (storagePolicy) Authorize(_ context.Context, p storage.Principal, action, id string, protection storage.Protection) error {
	if p != system {
		return storage.ErrDenied
	}
	return nil
}

type provider struct {
	clock  *clock
	mu     sync.Mutex
	files  map[string][]byte
	writes map[string]int
	hook   func()
}

func (p *provider) Verify(_ context.Context, i storage.Instance) (storage.InstanceEvidence, error) {
	return storage.InstanceEvidence{AccountDomain: "fixture:" + i.ID, ProviderFree: 1 << 20, Quota: &storage.ProviderQuotaSample{TotalBytes: 1 << 20}, VerifiedAt: p.clock.Now()}, nil
}
func (p *provider) Resolve(context.Context, storage.Instance) (storage.Driver, error) { return p, nil }
func (p *provider) Find(_ context.Context, i storage.Instance, intent string, _ storage.Locator) (storage.Locator, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.files[i.ID+":"+intent]; !ok {
		return storage.Locator{}, storage.ErrNotFound
	}
	return storage.Locator{ID: intent}, nil
}
func (p *provider) Write(_ context.Context, i storage.Instance, intent string, size int64, r io.Reader, checkpoint func(storage.Locator) error) (storage.Locator, error) {
	loc := storage.Locator{ID: intent}
	if e := checkpoint(loc); e != nil {
		return loc, e
	}
	b, e := io.ReadAll(io.LimitReader(r, size+1))
	if e != nil {
		return loc, e
	}
	if int64(len(b)) != size {
		return loc, storage.ErrIntegrity
	}
	p.mu.Lock()
	p.files[i.ID+":"+intent] = b
	p.writes[i.ID]++
	p.mu.Unlock()
	return loc, nil
}
func (p *provider) Read(_ context.Context, i storage.Instance, l storage.Locator, w io.Writer) (int64, error) {
	p.mu.Lock()
	b, ok := p.files[i.ID+":"+l.ID]
	b = bytes.Clone(b)
	hook := p.hook
	p.hook = nil
	p.mu.Unlock()
	if !ok {
		return 0, storage.ErrNotFound
	}
	if hook != nil {
		hook()
	}
	n, e := w.Write(b)
	return int64(n), e
}
func (p *provider) Remove(_ context.Context, i storage.Instance, l storage.Locator) error {
	p.mu.Lock()
	delete(p.files, i.ID+":"+l.ID)
	p.mu.Unlock()
	return nil
}

type fixture struct {
	s         *media.Service
	store     *storage.Service
	repo      *mp.Repository
	db, admin *sql.DB
	provider  *provider
	policy    *policy
	clock     *clock
	cfg       media.Config
	ctx       context.Context
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dsn := os.Getenv("STUHELPER_MEDIA_TEST_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL required")
	}
	control, e := sql.Open("pgx", dsn)
	must(t, e)
	t.Cleanup(func() { _ = control.Close() })
	var random [8]byte
	_, e = rand.Read(random[:])
	must(t, e)
	name := "media_test_" + hex.EncodeToString(random[:])
	mediaRole := name + "_media"
	storageRole := name + "_storage"
	_, e = control.Exec(`CREATE DATABASE ` + name)
	must(t, e)
	t.Cleanup(func() {
		if _, err := control.Exec(`DROP DATABASE ` + name + ` WITH (FORCE)`); err != nil {
			t.Error(err)
		}
		if _, err := control.Exec(`DROP ROLE IF EXISTS ` + mediaRole + `, ` + storageRole); err != nil {
			t.Error(err)
		}
	})
	admin, e := sql.Open("pgx", dsn+" dbname="+name)
	must(t, e)
	t.Cleanup(func() { _ = admin.Close() })
	_, e = admin.Exec(mp.Schema + sp.Schema)
	must(t, e)
	_, e = admin.Exec(fmt.Sprintf(`CREATE ROLE %s LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE; CREATE ROLE %s LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE;
 GRANT USAGE ON SCHEMA media TO %s; GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA media TO %s; REVOKE UPDATE,DELETE ON media.audit FROM %s;
 GRANT USAGE ON SCHEMA storage TO %s; GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA storage TO %s; REVOKE UPDATE,DELETE,TRUNCATE ON storage.audit FROM %s;
 REVOKE INSERT,UPDATE,DELETE,TRUNCATE ON storage.audit_retention FROM %s;
 REVOKE ALL ON SCHEMA public FROM PUBLIC;`, mediaRole, storageRole, mediaRole, mediaRole, mediaRole, storageRole, storageRole, storageRole, storageRole))
	must(t, e)
	db, e := sql.Open("pgx", dsn+" dbname="+name+" user="+mediaRole)
	must(t, e)
	t.Cleanup(func() { _ = db.Close() })
	db.SetMaxOpenConns(12)
	storageDB, e := sql.Open("pgx", dsn+" dbname="+name+" user="+storageRole)
	must(t, e)
	t.Cleanup(func() { _ = storageDB.Close() })
	storageDB.SetMaxOpenConns(12)
	c := &clock{t: time.Now().UTC()}
	p := &provider{files: map[string][]byte{}, writes: map[string]int{}}
	sr := &sp.Repository{DB: storageDB}
	must(t, sr.CheckRuntime(context.Background()))
	p.clock = c
	st, e := storage.New(sr, storagePolicy{}, p, p, storage.Config{Clock: c.Now, MaxObjectSize: 1 << 20, TemporaryDirectory: t.TempDir(), ParallelTransfers: 4, Lease: time.Minute, VerificationAge: time.Hour, MaxAttempts: 3})
	must(t, e)
	t.Cleanup(func() { _ = st.Close(context.Background()) })
	a := &policy{denied: map[string]bool{}}
	repo := &mp.Repository{DB: db}
	must(t, repo.CheckRuntime(context.Background()))
	cfg := media.Config{Profiles: map[string]media.Profile{"documents": {Module: "fixture", Quarantine: media.Protection{Class: "quarantine", Scope: "school"}, Published: media.Protection{Class: "public", Scope: "school", Public: true}, AllowedTypes: []string{"text/plain", "application/pdf"}, MaxSize: 1 << 20}}, Actor: system, Clock: c.Now, UploadTTL: 15 * time.Minute, UnreferencedTTL: time.Hour, OperationTimeout: time.Minute, ParallelTransfers: 4, MaxOpenUploads: 10, MaxFilesPerOwner: 100, MaxVersions: 10, MaxReferences: 10, MaxAttempts: 3}
	s, e := media.New(repo, a, st, cfg)
	must(t, e)
	t.Cleanup(func() { _ = s.Close(context.Background()) })
	h := &fixture{s, st, repo, db, admin, p, a, c, cfg, context.Background()}
	for n := 0; n < 3; n++ {
		id := fmt.Sprintf("account-%d", n)
		admissions := []storage.Admission{{Class: "public", Scope: "school", Plaintext: true, ExpiresAt: c.Now().Add(48 * time.Hour)}}
		i, err := storagetest.RegisterContribution(h.ctx, st, system, "register-"+id, storage.Instance{
			ID: id, Adapter: "fixture", OwnerDomain: storage.ContributionOwnerDomain(system), CredentialRef: id, CredentialRevision: 1, Root: "isolated",
			Limit: 1 << 20, Authorized: true, ExpiresAt: c.Now().Add(48 * time.Hour), Admissions: admissions,
		})
		must(t, err)
		if n < 2 {
			_, err = storagetest.Trust(h.ctx, st, system, i, "school", []string{"quarantine", "restricted"})
			must(t, err)
		}
	}
	return h
}
func must(t *testing.T, e error) {
	t.Helper()
	if e != nil {
		t.Fatal(e)
	}
}
func request(data []byte) media.UploadRequest {
	sum := sha256.Sum256(data)
	return media.UploadRequest{Purpose: "documents", Filename: "学习资料.txt", ContentType: "text/plain", Size: int64(len(data)), SHA256: hex.EncodeToString(sum[:])}
}
func (h *fixture) newUpload(t *testing.T, key string, data []byte) media.Version {
	t.Helper()
	v, e := h.s.CreateUpload(h.ctx, user, key, request(data))
	must(t, e)
	v, e = h.s.Upload(h.ctx, user, v.UploadID, "bytes", bytes.NewReader(data))
	must(t, e)
	return v
}
func (h *fixture) cycle(t *testing.T) {
	t.Helper()
	h.clock.Add(3 * time.Second)
	_, e := h.s.Sweep(h.ctx, 100, "")
	must(t, e)
	for n := 0; n < 4; n++ {
		_, e = h.s.RunOne(h.ctx, "fixture-worker")
		if e != nil && !errors.Is(e, media.ErrUnavailable) {
			t.Fatal(e)
		}
	}
	_, e = h.store.Reconcile(h.ctx, system, 100, "")
	must(t, e)
	for n := 0; n < 8; n++ {
		ran, e := h.store.RunOne(h.ctx, "storage-worker")
		must(t, e)
		if !ran {
			break
		}
	}
}
func (h *fixture) ready(t *testing.T, v media.Version) media.Version {
	t.Helper()
	_, e := h.s.Approve(h.ctx, user, v.ID, "approve")
	must(t, e)
	for n := 0; n < 8; n++ {
		h.cycle(t)
		st, e := h.s.GetVersion(h.ctx, user, v.ID)
		must(t, e)
		if st.State == "ready" && st.Healthy == 3 {
			return st.Version
		}
	}
	t.Fatal("file did not reach three replicas")
	return v
}
func (h *fixture) bind(t *testing.T, v media.Version, resource string) media.Reference {
	t.Helper()
	r, e := h.s.Attach(h.ctx, user, v.ID, "attach-"+resource, media.Binding{Module: "fixture", ResourceID: resource})
	must(t, e)
	r, e = h.s.Publish(h.ctx, user, r.ID, "publish-"+resource)
	must(t, e)
	if r.State != "active" {
		t.Fatal("reference not active")
	}
	return r
}
func (h *fixture) object(t *testing.T, id string) string {
	t.Helper()
	var v media.Version
	must(t, h.repo.Transaction(h.ctx, func(tx media.Transaction) error { var e error; v, e = tx.Version(id); return e }))
	return v.ObjectID
}

func TestUploadQuarantineApprovalAndReferenceLifecycle(t *testing.T) {
	h := newFixture(t)
	data := []byte("independent file content")
	v := h.newUpload(t, "create", data)
	if v.State != "awaiting_approval" {
		t.Fatal(v.State)
	}
	h.cycle(t)
	h.provider.mu.Lock()
	if h.provider.writes["account-2"] != 0 {
		t.Error("unapproved bytes reached a public-only account")
	}
	h.provider.mu.Unlock()
	pending, e := h.s.Attach(h.ctx, user, v.ID, "pending", media.Binding{Module: "fixture", ResourceID: "first"})
	must(t, e)
	if _, e = h.s.Publish(h.ctx, user, pending.ID, "before-approval"); !errors.Is(e, media.ErrConflict) {
		t.Fatal(e)
	}
	v = h.ready(t, v)
	first, e := h.s.Publish(h.ctx, user, pending.ID, "publish-first")
	must(t, e)
	second := h.bind(t, v, "second")
	var got bytes.Buffer
	must(t, h.s.Download(h.ctx, user, first.ID, &got))
	if !bytes.Equal(got.Bytes(), data) {
		t.Fatal("wrong content")
	}
	_, e = h.s.Release(h.ctx, user, first.ID, "release-first")
	must(t, e)
	if e = h.s.Download(h.ctx, user, first.ID, io.Discard); !errors.Is(e, media.ErrDenied) {
		t.Fatal("released reference still reads", e)
	}
	must(t, h.s.Download(h.ctx, user, second.ID, io.Discard))
	_, e = h.s.Release(h.ctx, user, second.ID, "release-second")
	must(t, e)
	if e = h.s.Download(h.ctx, user, second.ID, io.Discard); !errors.Is(e, media.ErrDenied) {
		t.Fatal(e)
	}
	for n := 0; n < 5; n++ {
		h.cycle(t)
	}
	st, e := h.s.GetVersion(h.ctx, user, v.ID)
	must(t, e)
	if !st.CleanupComplete || st.State != "deleted" {
		t.Fatal(st.State, st.CleanupComplete)
	}
	h.provider.mu.Lock()
	defer h.provider.mu.Unlock()
	if len(h.provider.files) != 0 {
		t.Fatal("physical files remain")
	}
}

func TestValidationExpiryAndConcurrentIdempotency(t *testing.T) {
	h := newFixture(t)
	data := []byte("valid text")
	var wg sync.WaitGroup
	ids := make(chan string, 12)
	for n := 0; n < 12; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, e := h.s.CreateUpload(h.ctx, user, "same", request(data))
			if e != nil {
				t.Error(e)
			}
			ids <- v.ID
		}()
	}
	wg.Wait()
	close(ids)
	id := ""
	for v := range ids {
		if id != "" && v != id {
			t.Fatal("duplicate version")
		}
		id = v
	}
	changed := request(data)
	changed.Filename = "changed.txt"
	if _, e := h.s.CreateUpload(h.ctx, user, "same", changed); !errors.Is(e, media.ErrConflict) {
		t.Fatal(e)
	}
	v, e := h.s.GetVersion(h.ctx, user, id)
	must(t, e)
	if _, e = h.s.Upload(h.ctx, user, v.UploadID, "bad-hash", bytes.NewReader([]byte("wrong text"))); !errors.Is(e, media.ErrIntegrity) {
		t.Fatal(e)
	}
	p := request([]byte("not a pdf"))
	p.ContentType = "application/pdf"
	pdf, e := h.s.CreateUpload(h.ctx, user, "pdf", p)
	must(t, e)
	if _, e = h.s.Upload(h.ctx, user, pdf.UploadID, "bad-type", strings.NewReader("not a pdf")); !errors.Is(e, media.ErrType) {
		t.Fatal(e)
	}
	orphan, e := h.s.CreateUpload(h.ctx, user, "expire", request(data))
	must(t, e)
	h.clock.Add(16 * time.Minute)
	h.cycle(t)
	status, e := h.s.GetVersion(h.ctx, user, orphan.ID)
	must(t, e)
	if status.State != "expired" || !status.CleanupComplete {
		t.Fatal(status.State, status.CleanupComplete)
	}
	h.provider.mu.Lock()
	defer h.provider.mu.Unlock()
	if len(h.provider.files) != 0 {
		t.Fatal("invalid upload wrote provider content")
	}
}

func TestImmutableVersionsOwnershipAndCurrentBusinessAuthorization(t *testing.T) {
	h := newFixture(t)
	data := []byte("version one")
	v := h.ready(t, h.newUpload(t, "one", data))
	r := h.bind(t, v, "one")
	next := request([]byte("version two"))
	next.FileID = v.FileID
	v2, e := h.s.CreateUpload(h.ctx, user, "two", next)
	must(t, e)
	if v2.FileID != v.FileID || v2.Number != 2 || v2.ID == v.ID {
		t.Fatal("version identity changed")
	}
	foreign := media.Principal{Issuer: user.Issuer, Subject: "another"}
	if _, e = h.s.CreateUpload(h.ctx, foreign, "foreign", next); !errors.Is(e, media.ErrDenied) {
		t.Fatal(e)
	}
	if _, e = h.s.Attach(h.ctx, user, v.ID, "foreign-ref", media.Binding{Module: "fixture", ResourceID: "foreign-business"}); !errors.Is(e, media.ErrDenied) {
		t.Fatal(e)
	}
	h.policy.deny("media.references.download", true)
	if e = h.s.Download(h.ctx, user, r.ID, io.Discard); !errors.Is(e, media.ErrDenied) {
		t.Fatal(e)
	}
	h.policy.deny("media.references.download", false)
	h.provider.mu.Lock()
	h.provider.hook = func() {
		f, e := h.s.GetFile(h.ctx, user, v.FileID)
		must(t, e)
		_, e = h.s.SetFileState(h.ctx, user, f.ID, "disable-during-read", f.Revision, true)
		must(t, e)
	}
	h.provider.mu.Unlock()
	var out bytes.Buffer
	if e = h.s.Download(h.ctx, user, r.ID, &out); !errors.Is(e, media.ErrDenied) || out.Len() != 0 {
		t.Fatal("disabled content escaped", e, out.Len())
	}
}

type lostStore struct {
	media.Store
	loseCreate, loseIngest bool
	afterReference         func()
}

func (s *lostStore) Create(ctx context.Context, p media.Principal, k string, r storage.CreateRequest) (storage.Status, error) {
	v, e := s.Store.Create(ctx, p, k, r)
	if e == nil && s.loseCreate {
		s.loseCreate = false
		return storage.Status{}, storage.ErrUnavailable
	}
	return v, e
}
func (s *lostStore) Ingest(ctx context.Context, p media.Principal, id, k string, r io.Reader) (storage.Status, error) {
	v, e := s.Store.Ingest(ctx, p, id, k, r)
	if e == nil && s.loseIngest {
		s.loseIngest = false
		return storage.Status{}, storage.ErrUnavailable
	}
	return v, e
}
func (s *lostStore) Reference(ctx context.Context, p media.Principal, id, k string, r storage.Reference, on bool) (storage.Status, error) {
	v, e := s.Store.Reference(ctx, p, id, k, r, on)
	if e == nil && s.afterReference != nil {
		f := s.afterReference
		s.afterReference = nil
		f()
	}
	return v, e
}
func TestRecoveryDoesNotDuplicateContentOrPublishFromStaleConsent(t *testing.T) {
	h := newFixture(t)
	must(t, h.s.Close(h.ctx))
	fault := &lostStore{Store: h.store, loseIngest: true}
	s, e := media.New(h.repo, h.policy, fault, h.cfg)
	must(t, e)
	h.s = s
	data := []byte("response lost")
	v, e := s.CreateUpload(h.ctx, user, "create", request(data))
	must(t, e)
	if _, e = s.Upload(h.ctx, user, v.UploadID, "upload", bytes.NewReader(data)); !errors.Is(e, media.ErrUnavailable) {
		t.Fatal(e)
	}
	must(t, s.Close(h.ctx))
	h.s, e = media.New(h.repo, h.policy, fault, h.cfg)
	must(t, e)
	h.cycle(t)
	status, e := h.s.GetVersion(h.ctx, user, v.ID)
	must(t, e)
	if status.State != "awaiting_approval" {
		t.Fatal(status.State)
	}
	v = h.ready(t, status.Version)
	ref, e := h.s.Attach(h.ctx, user, v.ID, "bind", media.Binding{Module: "fixture", ResourceID: "resume"})
	must(t, e)
	fault.afterReference = func() { h.policy.deny("media.references.publish", true) }
	if _, e = h.s.Publish(h.ctx, user, ref.ID, "publish"); !errors.Is(e, media.ErrDenied) {
		t.Fatal(e)
	}
	h.cycle(t)
	r, e := h.s.GetReference(h.ctx, user, ref.ID)
	must(t, e)
	if r.State == "active" {
		t.Fatal("background published stale consent")
	}
	h.policy.deny("media.references.publish", false)
	r, e = h.s.Publish(h.ctx, user, ref.ID, "publish")
	must(t, e)
	if r.State != "active" {
		t.Fatal(r.State)
	}
	var count int
	must(t, h.admin.QueryRow(`SELECT count(*) FROM storage.objects WHERE data->>'state' NOT IN ('deleted','deleting')`).Scan(&count))
	if count != 1 {
		t.Fatal("duplicated live storage object after protection migration", count)
	}
}

func TestDatabaseIsolationAtomicAuditAndDeleteWithReferences(t *testing.T) {
	h := newFixture(t)
	if e := (&mp.Repository{DB: h.admin}).CheckRuntime(h.ctx); !errors.Is(e, media.ErrDenied) {
		t.Fatal(e)
	}
	if _, e := h.db.Exec(`SELECT * FROM storage.objects`); e == nil {
		t.Fatal("media runtime read storage tables")
	}
	if _, e := h.db.Exec(`DELETE FROM media.audit`); e == nil {
		t.Fatal("runtime changed audit")
	}
	v := h.ready(t, h.newUpload(t, "content", []byte("retain referenced")))
	_ = h.bind(t, v, "business")
	file, e := h.s.GetFile(h.ctx, user, v.FileID)
	must(t, e)
	if _, e = h.s.DeleteFile(h.ctx, user, file.ID, "delete", file.Revision); !errors.Is(e, media.ErrConflict) {
		t.Fatal("deleted referenced file", e)
	}
	var audit, events int
	must(t, h.db.QueryRow(`SELECT (SELECT count(*) FROM media.audit),(SELECT count(*) FROM media.outbox)`).Scan(&audit, &events))
	if audit == 0 || audit != events {
		t.Fatal("audit and outbox diverged")
	}
	pending, e := h.repo.PendingEvents(h.ctx, 1)
	must(t, e)
	must(t, h.repo.AcknowledgeEvent(h.ctx, pending[0].ID))
}

func TestLostCreateAfterReplayWindowExpiresCleansOriginalObject(t *testing.T) {
	h := newFixture(t)
	must(t, h.s.Close(h.ctx))
	fault := &lostStore{Store: h.store, loseCreate: true}
	var e error
	h.s, e = media.New(h.repo, h.policy, fault, h.cfg)
	must(t, e)
	data := []byte("creation response missing")
	v, e := h.s.CreateUpload(h.ctx, user, "lost-create", request(data))
	must(t, e)
	if _, e = h.s.Upload(h.ctx, user, v.UploadID, "bytes", bytes.NewReader(data)); e != nil {
		t.Fatal(e)
	}
	h.clock.Add(25 * time.Hour)
	_, e = h.store.Reconcile(h.ctx, system, 100, "")
	must(t, e)
	for range 4 {
		h.cycle(t)
	}
	st, e := h.s.GetVersion(h.ctx, user, v.ID)
	must(t, e)
	if st.State != "expired" || !st.CleanupComplete {
		t.Fatal(st.State, st.CleanupComplete)
	}
	var count int
	must(t, h.admin.QueryRow(`SELECT count(*) FROM storage.objects`).Scan(&count))
	if count != 2 { // Each protection group has one reserved object.

		t.Fatal("created replacement object while recovering", count)
	}
}

type hookStore struct {
	media.Store
	ingestCalls int
	onIngest    func(id, k string, r io.Reader) error
}

func (s *hookStore) Ingest(ctx context.Context, p media.Principal, id, k string, r io.Reader) (storage.Status, error) {
	s.ingestCalls++
	if s.onIngest != nil {
		fn := s.onIngest
		s.onIngest = nil
		if err := fn(id, k, r); err != nil {
			return storage.Status{}, err
		}
	}
	return s.Store.Ingest(ctx, p, id, k, r)
}

func TestStaleUploadFinishCannotOverwriteApprovedOrPublishedVersion(t *testing.T) {
	h := newFixture(t)
	must(t, h.s.Close(h.ctx))
	wrapped := &hookStore{Store: h.store}
	s, e := media.New(h.repo, h.policy, wrapped, h.cfg)
	must(t, e)
	h.s = s

	data := []byte("published lecture slides")
	v, e := s.CreateUpload(h.ctx, user, "a02-create", request(data))
	must(t, e)

	var ref media.Reference
	wrapped.onIngest = func(id, k string, r io.Reader) error {
		// Bytes reached storage, then this Upload worker stalled past UploadUntil while
		// recovery promoted the version, moderation approved it, and a reference was published.
		_, err := h.store.Ingest(h.ctx, system, id, k, r)
		must(t, err)
		h.clock.Add(h.cfg.OperationTimeout + 5*time.Second)
		_, err = h.store.Reconcile(h.ctx, system, 100, "")
		must(t, err)
		h.cycle(t)
		ready := h.ready(t, v)
		ref = h.bind(t, ready, "a02-live-resource")
		return storage.ErrIntegrity
	}
	if _, e = s.Upload(h.ctx, user, v.UploadID, "a02-attempt-1", bytes.NewReader(data)); !errors.Is(e, media.ErrConflict) {
		t.Fatalf("stale timed-out upload returned %v, want ErrConflict", e)
	}

	st, e := s.GetVersion(h.ctx, user, v.ID)
	must(t, e)
	if st.State != "ready" || !st.Approved {
		t.Fatalf("stale finish overwrote published version state: %+v", st)
	}
	h.cycle(t)
	var got bytes.Buffer
	must(t, s.Download(h.ctx, user, ref.ID, &got))
	if !bytes.Equal(got.Bytes(), data) {
		t.Fatal("published content corrupted or deleted after stale upload finish")
	}
}

func TestUploadIdempotencyKeyAndVerifyingReconciliation(t *testing.T) {
	h := newFixture(t)
	must(t, h.s.Close(h.ctx))
	lost := &lostStore{Store: h.store}
	wrapped := &hookStore{Store: lost}
	s, e := media.New(h.repo, h.policy, wrapped, h.cfg)
	must(t, e)
	h.s = s

	data := []byte("idempotent upload body")
	v, e := s.CreateUpload(h.ctx, user, "a08-create-1", request(data))
	must(t, e)
	done, e := s.Upload(h.ctx, user, v.UploadID, "a08-key-1", bytes.NewReader(data))
	must(t, e)
	if done.State != "awaiting_approval" {
		t.Fatal(done.State)
	}
	ingestsAfterFirst := wrapped.ingestCalls

	// Same key + identical body replays original result without re-ingesting.
	replayed, e := s.Upload(h.ctx, user, v.UploadID, "a08-key-1", bytes.NewReader(data))
	must(t, e)
	if replayed.ID != done.ID || replayed.State != "awaiting_approval" || wrapped.ingestCalls != ingestsAfterFirst {
		t.Fatalf("unexpected replay result: %+v ingests=%d/%d", replayed, wrapped.ingestCalls, ingestsAfterFirst)
	}
	// Same key + different body must return 409 ErrConflict (MP-03).
	if _, e = s.Upload(h.ctx, user, v.UploadID, "a08-key-1", bytes.NewReader([]byte("different body"))); !errors.Is(e, media.ErrConflict) {
		t.Fatalf("same key with different bytes accepted: %v", e)
	}
	// Different key on already completed upload must return 409 ErrConflict.
	if _, e = s.Upload(h.ctx, user, v.UploadID, "a08-key-2", bytes.NewReader(data)); !errors.Is(e, media.ErrConflict) {
		t.Fatalf("different key on completed upload accepted: %v", e)
	}

	// Unconfirmed verifying upload checks storage.Status before re-streaming bytes.
	data2 := []byte("verifying retry without duplicate ingest")
	v2, e := s.CreateUpload(h.ctx, user, "a08-create-2", request(data2))
	must(t, e)
	lost.loseIngest = true
	if _, e = s.Upload(h.ctx, user, v2.UploadID, "a08-verify-key", bytes.NewReader(data2)); !errors.Is(e, media.ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable, got %v", e)
	}
	ingestsBeforeRetry := wrapped.ingestCalls
	if _, e = s.Upload(h.ctx, user, v2.UploadID, "a08-verify-key", bytes.NewReader([]byte("wrong retry bytes"))); !errors.Is(e, media.ErrConflict) {
		t.Fatalf("verifying retry with mismatched bytes accepted: %v", e)
	}
	recovered, e := s.Upload(h.ctx, user, v2.UploadID, "a08-verify-key", bytes.NewReader(data2))
	must(t, e)
	if recovered.State != "awaiting_approval" || wrapped.ingestCalls != ingestsBeforeRetry {
		t.Fatalf("verifying retry re-ingested bytes: state=%s ingests=%d/%d", recovered.State, wrapped.ingestCalls, ingestsBeforeRetry)
	}
}

func TestSweepRespectsActiveUploadLeaseAndConcurrentCancelRejectsUpload(t *testing.T) {
	h := newFixture(t)
	must(t, h.s.Close(h.ctx))
	wrapped := &hookStore{Store: h.store}
	cfg := h.cfg
	cfg.UploadTTL = time.Minute
	s, e := media.New(h.repo, h.policy, wrapped, cfg)
	must(t, e)
	h.s = s

	// 1. Upload started shortly before UploadTTL must not be killed mid-stream by Sweep.
	data := []byte("large file started near upload ttl")
	v, e := s.CreateUpload(h.ctx, user, "a09-near-ttl", request(data))
	must(t, e)
	h.clock.Add(cfg.UploadTTL - 10*time.Second)
	wrapped.onIngest = func(_, _ string, _ io.Reader) error {
		h.clock.Add(20 * time.Second)
		_, err := s.Sweep(h.ctx, 100, "")
		return err
	}
	completed, e := s.Upload(h.ctx, user, v.UploadID, "a09-stream-1", bytes.NewReader(data))
	must(t, e)
	if completed.State != "awaiting_approval" {
		t.Fatalf("Sweep killed active upload mid-stream: %+v", completed)
	}

	// 2. Concurrent CancelUpload during Ingest must make Upload return ErrConflict and allow immediate cleanup.
	data2 := []byte("cancelled while streaming")
	v2, e := s.CreateUpload(h.ctx, user, "a09-cancel-race", request(data2))
	must(t, e)
	wrapped.onIngest = func(_, _ string, _ io.Reader) error {
		_, err := s.CancelUpload(h.ctx, user, v2.UploadID, "a09-cancel")
		return err
	}
	if _, e = s.Upload(h.ctx, user, v2.UploadID, "a09-stream-2", bytes.NewReader(data2)); !errors.Is(e, media.ErrConflict) {
		t.Fatalf("concurrently cancelled upload returned %v instead of ErrConflict", e)
	}
	st, e := s.GetVersion(h.ctx, user, v2.ID)
	must(t, e)
	if st.State != "cancelled" || !st.UploadUntil.IsZero() {
		t.Fatalf("lease retained after writer returned: %s %s", st.State, st.UploadUntil)
	}
	// Media releases the handle, storage removes bytes, then media observes the
	// deletion. Other pending jobs may be claimed first in any of these polls.
	for i := 0; i < 4; i++ {
		h.cycle(t)
		st, e = s.GetVersion(h.ctx, user, v2.ID)
		must(t, e)
		if st.State == "cancelled" && st.CleanupComplete && st.StorageState == "deleted" {
			return
		}
	}
	t.Fatalf("cleanup did not finish before the old lease deadline: %s %v %s", st.State, st.CleanupComplete, st.StorageState)
}

type unavailableStatus struct{ media.Store }

func (s unavailableStatus) Status(context.Context, media.Principal, string) (storage.Status, error) {
	return storage.Status{}, storage.ErrUnavailable
}
func TestCleanupBackoffAndBlockedEvidence(t *testing.T) {
	h := newFixture(t)
	v := h.newUpload(t, "cleanup", []byte("cleanup"))
	_, e := h.s.CancelUpload(h.ctx, user, v.UploadID, "cancel")
	must(t, e)
	must(t, h.s.Close(h.ctx))
	h.s, e = media.New(h.repo, h.policy, unavailableStatus{h.store}, h.cfg)
	must(t, e)
	for i := 0; i < h.cfg.MaxAttempts; i++ {
		ran, e := h.s.RunOne(h.ctx, "worker")
		if !ran || !errors.Is(e, media.ErrUnavailable) {
			t.Fatal(ran, e)
		}
		_, e = h.s.Sweep(h.ctx, 100, "")
		must(t, e)
		if i+1 < h.cfg.MaxAttempts {
			delay := 5 * time.Second << i
			h.clock.Add(delay - time.Second)
			ran, e = h.s.RunOne(h.ctx, "worker")
			must(t, e)
			if ran {
				t.Fatal("retry before backoff elapsed", i)
			}
			h.clock.Add(time.Second)
		}
	}
	st, e := h.s.GetVersion(h.ctx, user, v.ID)
	must(t, e)
	if st.ErrorCode != media.ErrUnavailable.Error() || st.CleanupComplete || st.State != "cancelled" {
		t.Fatal(st.State, st.ErrorCode)
	}
	var count int
	must(t, h.db.QueryRow("SELECT count(*) FROM media.outbox WHERE data->>'type'='media.job.blocked.v1'").Scan(&count))
	if count != 1 {
		t.Fatal(count)
	}
}

type waitingPolicy struct {
	entered chan bool
	release chan struct{}
}

func (p waitingPolicy) Authorize(ctx context.Context, _ media.Principal, _ string, _ media.Access) error {
	_, ok := ctx.Deadline()
	p.entered <- ok
	select {
	case <-ctx.Done():
	case <-p.release:
	}
	<-p.release
	return ctx.Err()
}
func TestMetadataOperationDrainsOnClose(t *testing.T) {
	h := newFixture(t)
	v, e := h.s.CreateUpload(h.ctx, user, "create", request([]byte("x")))
	must(t, e)
	p := waitingPolicy{make(chan bool, 1), make(chan struct{})}
	s, e := media.New(h.repo, p, h.store, h.cfg)
	must(t, e)
	done := make(chan error, 1)
	go func() { _, e := s.GetVersion(h.ctx, user, v.ID); done <- e }()
	deadline := <-p.entered
	short, cancel := context.WithTimeout(h.ctx, 30*time.Millisecond)
	defer cancel()
	closeErr := s.Close(short)
	close(p.release)
	err := <-done
	must(t, s.Close(h.ctx))
	if !deadline || !errors.Is(closeErr, context.DeadlineExceeded) || err == nil {
		t.Fatalf("deadline=%v close=%v read=%v", deadline, closeErr, err)
	}
}
func TestOutboxPreservesWriteOrder(t *testing.T) {
	h := newFixture(t)
	for i, id := range []string{"zzz", "aaa"} {
		must(t, h.repo.Transaction(h.ctx, func(tx media.Transaction) error {
			return tx.Event(media.Event{ID: id, Subject: "lecture", Type: "media.fixture.v1", Time: h.clock.Now(), Revision: int64(i + 1)})
		}))
	}
	events, e := h.repo.PendingEvents(h.ctx, 1)
	must(t, e)
	if len(events) != 1 || events[0].ID != "zzz" || events[0].Data.Revision != 1 {
		t.Fatal(events)
	}
	must(t, h.repo.AcknowledgeEvent(h.ctx, events[0].ID))
	events, e = h.repo.PendingEvents(h.ctx, 1)
	must(t, e)
	if len(events) != 1 || events[0].ID != "aaa" {
		t.Fatal(events)
	}
}
func TestReferenceEventContextAndExcludedSubjects(t *testing.T) {
	h := newFixture(t)
	p := h.cfg.Profiles["documents"]
	p.SchoolID = "fixture-school"
	h.cfg.Profiles["documents"] = p
	s, e := media.New(h.repo, h.policy, h.store, h.cfg)
	must(t, e)
	defer s.Close(h.ctx)
	trace := "00-1234567890abcdef1234567890abcdef-1234567890abcdef-01"
	ctx := media.WithTraceParent(h.ctx, trace)
	v, e := s.CreateUpload(ctx, user, "v", request([]byte("lecture")))
	must(t, e)
	r, e := s.Attach(ctx, user, v.ID, "bind", media.Binding{Module: "fixture", ResourceID: "lecture"})
	must(t, e)
	other, e := s.CreateUpload(ctx, user, "other", request([]byte("other")))
	must(t, e)
	rows, e := h.repo.PendingOutbox(ctx, 1, []string{v.ID})
	must(t, e)
	if len(rows) != 1 || rows[0].Subject != other.ID {
		t.Fatal(rows)
	}
	rows, e = h.repo.PendingEvents(ctx, 10)
	must(t, e)
	ev := rows[1]
	if ev.Data.ReferenceID != r.ID || ev.Data.FileID != v.FileID || ev.Data.ResourceID != "lecture" || ev.Data.Module != "fixture" || ev.SchoolID != p.SchoolID || ev.TraceParent != trace {
		t.Fatal(ev)
	}
}
func TestOutboxMigrationAndCommitNotification(t *testing.T) {
	h := newFixture(t)
	listener, e := h.db.Conn(h.ctx)
	must(t, e)
	defer listener.Close()
	_, e = listener.ExecContext(h.ctx, "LISTEN media_outbox")
	must(t, e)
	emit := func(id string, rev int64, abort bool) error {
		return h.repo.Transaction(h.ctx, func(tx media.Transaction) error {
			if err := tx.Event(media.Event{ID: id, Type: "media.fixture.v1", Time: h.clock.Now(), Subject: "history", Revision: rev}); err != nil {
				return err
			}
			if abort {
				return media.ErrConflict
			}
			return nil
		})
	}
	if !errors.Is(emit("rollback", 3, true), media.ErrConflict) {
		t.Fatal("fixture did not roll back")
	}
	wait := func(d time.Duration) error {
		ctx, cancel := context.WithTimeout(h.ctx, d)
		defer cancel()
		return listener.Raw(func(raw any) error {
			n, e := raw.(*stdlib.Conn).Conn().WaitForNotification(ctx)
			if e == nil && (n.Channel != media.OutboxChannel || n.Payload != "") {
				t.Fatal(n)
			}
			return e
		})
	}
	if e = wait(40 * time.Millisecond); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal(e)
	}
	must(t, emit("later", 2, false))
	must(t, wait(time.Second))
	must(t, emit("earlier", 1, false))
	// Simulate the pre-sequence table, then run the real migration twice.
	_, e = h.admin.Exec("ALTER TABLE media.outbox DROP COLUMN seq")
	must(t, e)
	for i := 0; i < 2; i++ {
		_, e = h.admin.Exec(mp.Schema)
		must(t, e)
	}
	must(t, emit("newest", 3, false))
	rows, e := h.repo.PendingEvents(h.ctx, 10)
	must(t, e)
	if len(rows) != 3 || rows[0].ID != "earlier" || rows[1].ID != "later" || rows[2].ID != "newest" {
		t.Fatal(rows)
	}
}
func TestCleanedQuotaAndLiveReferenceLimit(t *testing.T) {
	h := newFixture(t)
	cfg := h.cfg
	cfg.MaxFilesPerOwner = 1
	cfg.MaxReferences = 2
	s, e := media.New(h.repo, h.policy, h.store, cfg)
	must(t, e)
	defer s.Close(h.ctx)
	v, e := s.CreateUpload(h.ctx, user, "first", request([]byte("a")))
	must(t, e)
	_, e = s.CancelUpload(h.ctx, user, v.UploadID, "cancel")
	must(t, e)
	h.cycle(t)
	page, e := s.ListFiles(h.ctx, user, 10, "")
	must(t, e)
	if len(page.Items) != 0 {
		t.Fatal("cleaned file still listed")
	}
	v, e = s.CreateUpload(h.ctx, user, "second", request([]byte("b")))
	must(t, e)
	attach := func(id string) (media.Reference, error) {
		return s.Attach(h.ctx, user, v.ID, id, media.Binding{Module: "fixture", ResourceID: id})
	}
	a, e := attach("one")
	must(t, e)
	_, e = attach("two")
	must(t, e)
	_, e = attach("three")
	if !errors.Is(e, media.ErrCapacity) {
		t.Fatal(e)
	}
	_, e = s.Release(h.ctx, user, a.ID, "release")
	must(t, e)
	_, e = attach("three")
	must(t, e)
	r, e := s.GetReference(h.ctx, user, a.ID)
	must(t, e)
	if r.State != "released" {
		t.Fatal(r)
	}
}
func TestDeletedFileRetiresAfterAllVersionsClean(t *testing.T) {
	h := newFixture(t)
	v := h.newUpload(t, "first", []byte("lecture"))
	q := request([]byte("notes"))
	q.FileID = v.FileID
	_, e := h.s.CreateUpload(h.ctx, user, "second", q)
	must(t, e)
	f, e := h.s.GetFile(h.ctx, user, v.FileID)
	must(t, e)
	_, e = h.s.DeleteFile(h.ctx, user, f.ID, "remove", f.Revision)
	must(t, e)
	for i := 0; i < 5; i++ {
		h.cycle(t)
	}
	f, e = h.s.GetFile(h.ctx, user, f.ID)
	must(t, e)
	if f.Deleting || !f.Disabled || len(f.Versions) != 2 {
		t.Fatal(f)
	}
	for _, v := range f.Versions {
		if !v.CleanupComplete {
			t.Fatal(v.ID)
		}
	}
	page, e := h.s.ListFiles(h.ctx, user, 1, "")
	must(t, e)
	if len(page.Items) != 0 {
		t.Fatal(page)
	}
	// Backfill the tombstone of a file cleaned with the old schema.
	_, e = h.admin.Exec(`UPDATE media.files SET data=(data-'retired')||'{"deleting":true}'::jsonb WHERE id=$1`, f.ID)
	must(t, e)
	for i := 0; i < 2; i++ {
		_, e = h.admin.Exec(mp.Schema)
		must(t, e)
	}
	f, e = h.s.GetFile(h.ctx, user, f.ID)
	must(t, e)
	if f.Deleting || !f.Retired {
		t.Fatal(f.File)
	}
}

type countedRepo struct {
	media.Repository
	txs int
}

func (r *countedRepo) Transaction(ctx context.Context, fn func(media.Transaction) error) error {
	r.txs++
	return r.Repository.Transaction(ctx, fn)
}
func TestManifestUsesOneSnapshot(t *testing.T) {
	h := newFixture(t)
	v := h.ready(t, h.newUpload(t, "lecture", []byte("lecture")))
	ids := []string{h.bind(t, v, "a").ID, h.bind(t, v, "b").ID}
	r := &countedRepo{Repository: h.repo}
	s, e := media.New(r, h.policy, h.store, h.cfg)
	must(t, e)
	defer s.Close(h.ctx)
	manifest, e := s.ArchiveManifest(h.ctx, user, ids)
	must(t, e)
	if r.txs > 1 || len(manifest.Entries) != 2 || manifest.Entries[1].ReferenceID != ids[1] {
		t.Fatal(r.txs, manifest)
	}
	r.txs = 0
	var archive bytes.Buffer
	must(t, s.Archive(h.ctx, user, ids, &archive))
	if r.txs != 2+2*len(ids) || archive.Len() == 0 {
		t.Fatal("archive media transactions", r.txs)
	}
}
func TestMetadataReadsUseCommittedSnapshotsDuringWriteLock(t *testing.T) {
	h := newFixture(t)
	v := h.newUpload(t, "file", []byte("lecture"))
	ref, e := h.s.Attach(h.ctx, user, v.ID, "bind", media.Binding{Module: "fixture", ResourceID: "draft"})
	must(t, e)
	tx, e := h.db.BeginTx(h.ctx, nil)
	must(t, e)
	defer tx.Rollback()
	_, e = tx.Exec("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", "stuhelper-media:file:"+v.FileID)
	must(t, e)
	ctx, cancel := context.WithTimeout(h.ctx, 2*time.Second)
	defer cancel()
	file, e := h.s.GetFile(ctx, user, v.FileID)
	must(t, e)
	upload, e := h.s.GetUpload(ctx, user, v.UploadID)
	must(t, e)
	bound, e := h.s.GetReference(ctx, user, ref.ID)
	must(t, e)
	if len(file.Versions) != 1 || file.Versions[0].ID != upload.ID || bound.VersionID != v.ID {
		t.Fatal(file.ID, upload.ID, bound.ID)
	}
}
func TestReviewAuditAndFileEnableEvent(t *testing.T) {
	h := newFixture(t)
	v := h.newUpload(t, "create", []byte("review"))
	must(t, h.s.ReviewDownload(h.ctx, user, v.ID, io.Discard))
	var count int
	must(t, h.db.QueryRow("SELECT count(*) FROM media.audit WHERE data->'event'->>'subject'=$1 AND data->'event'->>'type'='media.version.reviewed.v1'", v.ID).Scan(&count))
	if count != 1 {
		t.Fatal("review audit count", count)
	}
	f, e := h.s.GetFile(h.ctx, user, v.FileID)
	must(t, e)
	f, e = h.s.SetFileState(h.ctx, user, f.ID, "off", f.Revision, true)
	must(t, e)
	f, e = h.s.SetFileState(h.ctx, user, f.ID, "on", f.Revision, false)
	must(t, e)
	must(t, h.db.QueryRow("SELECT count(*) FROM media.outbox WHERE data->>'type'='media.files.enable.v1' AND data->>'subject'=$1", f.ID).Scan(&count))
	if f.Disabled || count != 1 {
		t.Fatal(f.Disabled, count)
	}
}
func TestReplayExpiryAndReleasedHistory(t *testing.T) {
	h := newFixture(t)
	req := request([]byte("fixture"))
	v, e := h.s.CreateUpload(h.ctx, user, "create", req)
	must(t, e)
	bind := func(id string) media.Reference {
		r, e := h.s.Attach(h.ctx, user, v.ID, id, media.Binding{Module: "fixture", ResourceID: id})
		must(t, e)
		return r
	}
	a, b := bind("a"), bind("b")
	old, e := h.s.Release(h.ctx, user, a.ID, "release")
	must(t, e)
	_, e = h.s.CancelUpload(h.ctx, user, v.UploadID, "stop")
	must(t, e)
	oldAgain, e := h.s.GetReference(h.ctx, user, a.ID)
	must(t, e)
	newly, e := h.s.GetReference(h.ctx, user, b.ID)
	must(t, e)
	var events int
	must(t, h.db.QueryRow("SELECT count(*) FROM media.outbox WHERE data->>'type'='media.reference.released.v1'").Scan(&events))
	var forced int
	must(t, h.db.QueryRow("SELECT count(*) FROM media.outbox WHERE data->>'type'='media.reference.released.v1' AND data->'data'->>'reference_id'=$1 AND data->'data'->>'file_id'=$2 AND data->'data'->>'resource_id'=$3 AND data->'data'->>'module'=$4", b.ID, v.FileID, b.ResourceID, b.Module).Scan(&forced))
	if forced != 1 {
		t.Fatal(forced)
	}
	if oldAgain.Revision != old.Revision || newly.Revision != b.Revision+1 || events != 2 {
		t.Fatal(oldAgain, newly, events)
	}
	h.clock.Add(24*time.Hour - time.Second)
	replay, e := h.s.CreateUpload(h.ctx, user, "create", req)
	must(t, e)
	if replay.ID != v.ID {
		t.Fatal("early expiry")
	}
	h.clock.Add(time.Second)
	h.refreshQuota(t)
	next, e := h.s.CreateUpload(h.ctx, user, "create", req)
	must(t, e)
	if next.ID == v.ID {
		t.Fatal("expired response replayed")
	}
	_, e = h.s.Sweep(h.ctx, 100, "")
	must(t, e)
	var expired int
	must(t, h.db.QueryRow("SELECT count(*) FROM media.replays WHERE expires_at<=$1", h.clock.Now()).Scan(&expired))
	if expired != 0 {
		t.Fatal(expired)
	}
}
func TestRuntimeRejectsAuditTruncate(t *testing.T) {
	h := newFixture(t)
	var role string
	must(t, h.db.QueryRow("SELECT current_user").Scan(&role))
	_, e := h.admin.Exec("GRANT TRUNCATE ON media.audit TO " + role)
	must(t, e)
	if !errors.Is(h.repo.CheckRuntime(h.ctx), media.ErrDenied) {
		t.Fatal("runtime accepted audit truncation privilege")
	}
}
func TestRuntimeRejectsSchemaOwnerMembership(t *testing.T) {
	h := newFixture(t)
	var runtime string
	must(t, h.db.QueryRow("SELECT current_user").Scan(&runtime))
	owner := runtime + "_owner"
	_, e := h.admin.Exec("CREATE ROLE " + owner + " NOLOGIN")
	must(t, e)
	t.Cleanup(func() {
		_, e := h.admin.Exec("REASSIGN OWNED BY " + owner + " TO CURRENT_USER")
		if e != nil {
			t.Error(e)
		}
		_, e = h.admin.Exec("DROP ROLE " + owner)
		if e != nil {
			t.Error(e)
		}
	})
	_, e = h.admin.Exec("ALTER SCHEMA media OWNER TO " + owner)
	must(t, e)
	_, e = h.admin.Exec("GRANT " + owner + " TO " + runtime)
	must(t, e)
	if !errors.Is(h.repo.CheckRuntime(h.ctx), media.ErrDenied) {
		t.Fatal("runtime accepted schema owner membership")
	}
}
func TestReusePlanStartsWithOwner(t *testing.T) {
	h := newFixture(t)
	v := h.newUpload(t, "sample", []byte("common textbook"))
	var owner string
	must(t, h.db.QueryRow("SELECT owner_key FROM media.files WHERE id=$1", v.FileID).Scan(&owner))
	_, e := h.admin.Exec(`INSERT INTO media.files(id,owner_key,data) SELECT 'sample-'||n,'owner-'||n,data FROM media.files CROSS JOIN generate_series(1,2000)n WHERE id=$1`, v.FileID)
	must(t, e)
	_, e = h.admin.Exec(`INSERT INTO media.versions(id,file_id,upload_id,number,state,data) SELECT 'ver-'||n,'sample-'||n,'session-'||n,1,state,data FROM media.versions CROSS JOIN generate_series(1,2000)n WHERE id=$1`, v.ID)
	must(t, e)
	_, e = h.admin.Exec("ANALYZE media.files; ANALYZE media.versions")
	must(t, e)
	// Exercise the exact repository statement so the test tracks its predicates.
	h.db.SetMaxOpenConns(1)
	must(t, h.repo.Transaction(h.ctx, func(tx media.Transaction) error {
		_, e := tx.ReuseCandidates(user, request([]byte("common textbook")))
		return e
	}))
	var query string
	must(t, h.db.QueryRow("SELECT statement FROM pg_prepared_statements WHERE statement LIKE 'SELECT v.data FROM media.versions v JOIN media.files f%' AND statement LIKE '%LIMIT 10'").Scan(&query))
	rows, e := h.db.Query("EXPLAIN (ANALYZE,BUFFERS,COSTS OFF) "+query, owner, "documents", v.SHA256, v.Size, v.ContentType)
	must(t, e)
	defer rows.Close()
	var plan strings.Builder
	for rows.Next() {
		var line string
		must(t, rows.Scan(&line))
		plan.WriteString(line + "\n")
	}
	must(t, rows.Err())
	if !strings.Contains(plan.String(), "media_owner_content_reuse") {
		t.Fatal(plan.String())
	}
}

type gatedReader struct {
	prefix  []byte
	rest    []byte
	started chan struct{}
	release chan struct{}
	stage   int
}

func (g *gatedReader) Read(p []byte) (int, error) {
	switch g.stage {
	case 0:
		g.stage = 1
		n := copy(p, g.prefix)
		close(g.started)
		return n, nil
	case 1:
		<-g.release
		g.stage = 2
		n := copy(p, g.rest)
		return n, nil
	default:
		return 0, io.EOF
	}
}

func TestUploadLeaseConcurrencyAndReviewDownloadBoundaries(t *testing.T) {
	h := newFixture(t)
	data := []byte("streaming upload guarded by active lease")
	created, e := h.s.CreateUpload(h.ctx, user, "lease-create", request(data))
	must(t, e)

	var early bytes.Buffer
	if e = h.s.ReviewDownload(h.ctx, user, created.ID, &early); !errors.Is(e, media.ErrDenied) || early.Len() != 0 {
		t.Fatal("unverified created version served to reviewer", e, early.Len())
	}

	gate := &gatedReader{
		prefix:  data[:16],
		rest:    data[16:],
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	done := make(chan error, 1)
	go func() {
		_, err := h.s.Upload(h.ctx, user, created.UploadID, "lease-u1", gate)
		done <- err
	}()
	<-gate.started

	if _, e = h.s.Upload(h.ctx, user, created.UploadID, "lease-u2", bytes.NewReader(data)); !errors.Is(e, media.ErrConflict) {
		t.Fatal("concurrent upload accepted during active lease", e)
	}
	if _, e = h.s.RunOne(h.ctx, "lease-worker"); e != nil {
		t.Fatal("background worker failed during active lease", e)
	}
	close(gate.release)
	must(t, <-done)

	st, e := h.s.GetVersion(h.ctx, user, created.ID)
	must(t, e)
	if st.State != "awaiting_approval" {
		t.Fatal("unexpected state after leased upload finished", st.State)
	}

	h.provider.mu.Lock()
	h.provider.hook = func() {
		f, err := h.s.GetFile(h.ctx, user, created.FileID)
		must(t, err)
		_, err = h.s.SetFileState(h.ctx, user, f.ID, "disable-during-review", f.Revision, true)
		must(t, err)
	}
	h.provider.mu.Unlock()
	var reviewOut bytes.Buffer
	if e = h.s.ReviewDownload(h.ctx, user, created.ID, &reviewOut); !errors.Is(e, media.ErrDenied) || reviewOut.Len() != 0 {
		t.Fatal("disabled file bytes leaked during review download", e, reviewOut.Len())
	}
}

func TestRepeatedBindingsRespectHandleLifetime(t *testing.T) {
	h := newFixture(t)
	must(t, h.s.Close(h.ctx))
	cfg := h.cfg
	cfg.PendingApprovalTTL = 24 * time.Hour
	var err error
	h.s, err = media.New(h.repo, h.policy, h.store, cfg)
	must(t, err)
	created := h.clock.Now()
	v := h.newUpload(t, "retention-limit", []byte("pending"))
	for _, key := range []string{"first", "second"} {
		h.clock.Add(25 * time.Minute)
		_, err = h.s.Attach(h.ctx, user, v.ID, key, media.Binding{Module: "fixture", ResourceID: key})
		must(t, err)
		got, err := h.s.GetVersion(h.ctx, user, v.ID)
		must(t, err)
		if !got.RetainUntil.Equal(created.Add(24 * time.Hour)) {
			t.Fatalf("retention deadline %v, want %v", got.RetainUntil, created.Add(24*time.Hour))
		}
	}
}

func TestVersionRejectionReasonCleanupAndPendingApprovalRetention(t *testing.T) {
	h := newFixture(t)
	badCfg := h.cfg
	badCfg.PendingApprovalTTL = 30 * time.Minute
	if _, e := media.New(h.repo, h.policy, h.store, badCfg); !errors.Is(e, media.ErrInput) {
		t.Fatal("accepted PendingApprovalTTL shorter than UnreferencedTTL", e)
	}
	badCfg.PendingApprovalTTL = 25 * time.Hour
	if _, e := media.New(h.repo, h.policy, h.store, badCfg); !errors.Is(e, media.ErrInput) {
		t.Fatal("accepted PendingApprovalTTL exceeding storage temporary window", e)
	}
	must(t, h.s.Close(h.ctx))
	cfg := h.cfg
	cfg.UnreferencedTTL = time.Hour
	cfg.PendingApprovalTTL = 12 * time.Hour
	var e error
	h.s, e = media.New(h.repo, h.policy, h.store, cfg)
	must(t, e)

	orphan := h.newUpload(t, "orphan-short", []byte("orphan awaiting approval"))
	submitted := h.newUpload(t, "submitted-pending", []byte("bound to pending submission"))
	approved := h.ready(t, h.newUpload(t, "already-approved", []byte("approved content")))
	if _, e = h.s.Reject(h.ctx, user, approved.ID, "reject-approved", media.ReasonPolicyViolation); !errors.Is(e, media.ErrConflict) {
		t.Fatal("rejected an already approved version", e)
	}
	ref, e := h.s.Attach(h.ctx, user, submitted.ID, "bind-submission", media.Binding{Module: "fixture", ResourceID: "submission-1"})
	must(t, e)
	if ref.State != "pending" {
		t.Fatal("unexpected reference state", ref.State)
	}

	h.clock.Add(2 * time.Hour)
	for n := 0; n < 3; n++ {
		h.cycle(t)
	}

	orphanView, e := h.s.GetVersion(h.ctx, user, orphan.ID)
	must(t, e)
	if orphanView.State != "expired" || !orphanView.CleanupComplete {
		t.Fatalf("orphan should expire after UnreferencedTTL: %+v", orphanView)
	}
	submittedView, e := h.s.GetVersion(h.ctx, user, submitted.ID)
	must(t, e)
	if submittedView.State != "awaiting_approval" || submittedView.CleanupComplete {
		t.Fatalf("bound pending version expired prematurely: %+v", submittedView)
	}

	if _, e = h.s.Reject(h.ctx, user, submitted.ID, "bad-reason", "unknown_reason"); !errors.Is(e, media.ErrInput) {
		t.Fatal("accepted unknown rejection reason", e)
	}
	h.refreshQuota(t)
	unverified, e := h.s.CreateUpload(h.ctx, user, "unverified", request([]byte("not uploaded yet")))
	must(t, e)
	if _, e = h.s.Reject(h.ctx, user, unverified.ID, "reject-created", media.ReasonPolicyViolation); !errors.Is(e, media.ErrConflict) {
		t.Fatal("rejected unuploaded session", e)
	}
	h.policy.deny("media.versions.reject", true)
	if _, e = h.s.Reject(h.ctx, user, submitted.ID, "denied-reject", media.ReasonCopyrightViolation); !errors.Is(e, media.ErrDenied) {
		t.Fatal("unauthorized rejection succeeded", e)
	}
	h.policy.deny("media.versions.reject", false)

	rejected, e := h.s.Reject(h.ctx, user, submitted.ID, "reject-key", media.ReasonCopyrightViolation)
	must(t, e)
	if rejected.State != "rejected" || rejected.RejectionReason != media.ReasonCopyrightViolation || rejected.ErrorCode != "media_rejected_copyright_violation" {
		t.Fatalf("unexpected rejected version: %+v", rejected)
	}
	replay, e := h.s.Reject(h.ctx, user, submitted.ID, "reject-key", media.ReasonCopyrightViolation)
	must(t, e)
	if replay.Revision != rejected.Revision || replay.RejectionReason != media.ReasonCopyrightViolation {
		t.Fatal("rejection replay changed state")
	}
	if _, e = h.s.Reject(h.ctx, user, submitted.ID, "reject-key", media.ReasonWrongCourse); !errors.Is(e, media.ErrConflict) {
		t.Fatal("same idempotency key accepted different reason", e)
	}
	sameReasonNewKey, e := h.s.Reject(h.ctx, user, submitted.ID, "reject-key-2", media.ReasonCopyrightViolation)
	must(t, e)
	if sameReasonNewKey.Revision != rejected.Revision {
		t.Fatal("idempotent same-reason rejection incremented revision")
	}
	if _, e = h.s.Reject(h.ctx, user, submitted.ID, "reject-key-3", media.ReasonWrongCourse); !errors.Is(e, media.ErrConflict) {
		t.Fatal("different rejection reason overwrote terminal reason", e)
	}
	if _, e = h.s.Approve(h.ctx, user, submitted.ID, "approve-after-reject"); !errors.Is(e, media.ErrConflict) {
		t.Fatal("approved a rejected version", e)
	}
	refAfter, e := h.s.GetReference(h.ctx, user, ref.ID)
	must(t, e)
	if refAfter.State != "released" {
		t.Fatalf("pending reference not released on rejection: %+v", refAfter)
	}

	for n := 0; n < 5; n++ {
		h.cycle(t)
	}
	cleaned, e := h.s.GetVersion(h.ctx, user, submitted.ID)
	must(t, e)
	if !cleaned.CleanupComplete || cleaned.State != "rejected" || cleaned.RejectionReason != media.ReasonCopyrightViolation {
		t.Fatalf("rejected version did not finish physical cleanup: %+v", cleaned)
	}

	var rejectedEvents int
	must(t, h.db.QueryRow(`SELECT count(*) FROM media.outbox WHERE data->>'type'='media.version.rejected.v1' AND data->>'subject'=$1`, submitted.ID).Scan(&rejectedEvents))
	if rejectedEvents != 1 {
		t.Fatalf("expected 1 media.version.rejected.v1 event, got %d", rejectedEvents)
	}
}

type failingReader struct {
	data []byte
	pos  int
}

func (r *failingReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.ErrUnexpectedEOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	if r.pos >= len(r.data) {
		return n, io.ErrUnexpectedEOF
	}
	return n, nil
}

type createProtectionPolicy struct {
	media.Authorizer
	allowed media.Protection
}

func (p createProtectionPolicy) Authorize(ctx context.Context, actor media.Principal, action string, a media.Access) error {
	if action == "media.uploads.create" && a.Protection != p.allowed {
		return media.ErrDenied
	}
	return p.Authorizer.Authorize(ctx, actor, action, a)
}

func TestResumableChunkUploadAndProfileCatalog(t *testing.T) {
	h := newFixture(t)
	t.Run("catalog and reuse check the upload classification", func(t *testing.T) {
		profile := h.cfg.Profiles["documents"]
		for _, allowed := range []media.Protection{profile.Published, profile.Quarantine} {
			checker, err := media.New(h.repo, createProtectionPolicy{h.policy, allowed}, h.store, h.cfg)
			must(t, err)
			defer checker.Close(h.ctx)
			catalog, err := checker.ListProfiles(h.ctx, user)
			must(t, err)
			q := request([]byte("quarantine purpose"))
			q.ReuseExisting = true
			_, err = checker.CreateUpload(h.ctx, user, "purpose-reuse", q)
			if allowed == profile.Quarantine {
				if len(catalog.Profiles) != 1 || err != nil {
					t.Fatalf("upload protection rejected: purposes=%d err=%v", len(catalog.Profiles), err)
				}
			} else if len(catalog.Profiles) != 0 || !errors.Is(err, media.ErrDenied) {
				t.Fatalf("public-only purpose: purposes=%d err=%v", len(catalog.Profiles), err)
			}
		}
	})
	stagingDir := t.TempDir()
	must(t, h.s.Close(h.ctx))
	cfg := h.cfg
	cfg.StagingDirectory = stagingDir
	cfg.MaxStagingBytes = 1 << 20
	var e error
	h.s, e = media.New(h.repo, h.policy, h.store, cfg)
	must(t, e)

	catalog, e := h.s.ListProfiles(h.ctx, user)
	must(t, e)
	if len(catalog.Profiles) != 1 || catalog.Profiles[0].Purpose != "documents" || catalog.Profiles[0].MaxSize != 1<<20 || catalog.UploadTTLSeconds != 900 {
		t.Fatalf("unexpected profile catalog: %+v", catalog)
	}
	h.policy.deny("media.uploads.create", true)
	deniedCatalog, e := h.s.ListProfiles(h.ctx, user)
	must(t, e)
	if len(deniedCatalog.Profiles) != 0 {
		t.Fatalf("denied purpose leaked in catalog: %+v", deniedCatalog)
	}
	h.policy.deny("media.uploads.create", false)

	payload := bytes.Repeat([]byte("chunked-lecture-notes-"), 60)
	created, e := h.s.CreateUpload(h.ctx, user, "chunk-create", request(payload))
	must(t, e)
	if created.UploadedBytes != 0 {
		t.Fatal("expected initial uploaded_bytes=0", created.UploadedBytes)
	}

	c1, e := h.s.AppendUpload(h.ctx, user, created.UploadID, "chunk-1", 0, bytes.NewReader(payload[:400]))
	must(t, e)
	if c1.State != "uploading" || c1.UploadedBytes != 400 {
		t.Fatalf("unexpected first chunk state: %+v", c1)
	}
	replay1, e := h.s.AppendUpload(h.ctx, user, created.UploadID, "chunk-1", 0, bytes.NewReader(payload[:400]))
	must(t, e)
	if replay1.UploadedBytes != 400 || replay1.Revision != c1.Revision {
		t.Fatalf("chunk replay mutated state: %+v", replay1)
	}
	if _, e = h.s.AppendUpload(h.ctx, user, created.UploadID, "chunk-1", 0, bytes.NewReader([]byte("tampered"))); !errors.Is(e, media.ErrConflict) {
		t.Fatal("same chunk key accepted different payload", e)
	}
	if _, e = h.s.AppendUpload(h.ctx, user, created.UploadID, "chunk-wrong-offset", 0, bytes.NewReader(payload[:100])); !errors.Is(e, media.ErrConflict) {
		t.Fatal("accepted stale offset", e)
	}

	// Simulate mid-chunk network drop: partial bytes must roll back to offset 400.
	if _, e = h.s.AppendUpload(h.ctx, user, created.UploadID, "chunk-2-drop", 400, &failingReader{data: payload[400:550]}); !errors.Is(e, media.ErrUnavailable) {
		t.Fatal("expected unavailable on dropped chunk stream", e)
	}
	inspected, e := h.s.GetUpload(h.ctx, user, created.UploadID)
	must(t, e)
	if inspected.UploadedBytes != 400 || inspected.State != "uploading" {
		t.Fatalf("interrupted chunk corrupted progress: %+v", inspected)
	}

	// Restart service on the same persistent StagingDirectory and resume from 400.
	must(t, h.s.Close(h.ctx))
	// A stopped writer persisted a suffix before its offset transaction committed.
	part, err := os.OpenFile(filepath.Join(stagingDir, "media-staging-v1", "upload-"+created.ID+".part"), os.O_APPEND|os.O_WRONLY, 0600)
	must(t, err)
	_, err = part.Write([]byte("uncommitted"))
	must(t, err)
	must(t, part.Close())

	h.s, e = media.New(h.repo, h.policy, h.store, cfg)
	must(t, e)
	afterRestart, e := h.s.GetUpload(h.ctx, user, created.UploadID)
	must(t, e)
	if afterRestart.UploadedBytes != 400 {
		t.Fatalf("persistent staging lost progress across restart: %+v", afterRestart)
	}

	c2, e := h.s.AppendUpload(h.ctx, user, created.UploadID, "chunk-2", 400, bytes.NewReader(payload[400:900]))
	must(t, e)
	if c2.UploadedBytes != 900 || c2.State != "uploading" {
		t.Fatalf("unexpected second chunk state: %+v", c2)
	}
	done, e := h.s.AppendUpload(h.ctx, user, created.UploadID, "chunk-3", 900, bytes.NewReader(payload[900:]))
	must(t, e)
	if done.State != "awaiting_approval" || done.UploadedBytes != int64(len(payload)) {
		t.Fatalf("final chunk did not complete verification: %+v", done)
	}
	ready := h.ready(t, done)
	ref := h.bind(t, ready, "chunked-resource")
	var downloaded bytes.Buffer
	must(t, h.s.Download(h.ctx, user, ref.ID, &downloaded))
	if !bytes.Equal(downloaded.Bytes(), payload) {
		t.Fatal("downloaded bytes mismatch after resumable upload")
	}

	// MIME mismatch on first chunk (>=512 bytes) is rejected immediately.
	badBody := bytes.Repeat([]byte("not-a-pdf-"), 60)
	pdfReq := request(badBody)
	pdfReq.ContentType = "application/pdf"
	pdfUp, e := h.s.CreateUpload(h.ctx, user, "bad-pdf-chunk", pdfReq)
	must(t, e)
	if _, e = h.s.AppendUpload(h.ctx, user, pdfUp.UploadID, "pdf-c1", 0, bytes.NewReader(badBody[:520])); !errors.Is(e, media.ErrType) {
		t.Fatal("expected ErrType on invalid first chunk prefix", e)
	}

	// Staging budget enforcement and release on cancel.
	must(t, h.s.Close(h.ctx))
	smallCfg := cfg
	smallCfg.StagingDirectory = t.TempDir()
	smallCfg.Profiles = map[string]media.Profile{
		"documents": {
			Module:       "fixture",
			Quarantine:   cfg.Profiles["documents"].Quarantine,
			Published:    cfg.Profiles["documents"].Published,
			AllowedTypes: []string{"text/plain"},
			MaxSize:      600,
		},
	}
	smallCfg.MaxStagingBytes = 600
	h.s, e = media.New(h.repo, h.policy, h.store, smallCfg)
	must(t, e)

	pA := bytes.Repeat([]byte("a"), 500)
	pB := bytes.Repeat([]byte("b"), 500)
	uA, e := h.s.CreateUpload(h.ctx, user, "budget-a", request(pA))
	must(t, e)
	uB, e := h.s.CreateUpload(h.ctx, user, "budget-b", request(pB))
	must(t, e)
	_, e = h.s.AppendUpload(h.ctx, user, uA.UploadID, "ba-1", 0, bytes.NewReader(pA[:400]))
	must(t, e)
	if _, e = h.s.AppendUpload(h.ctx, user, uB.UploadID, "bb-1", 0, bytes.NewReader(pB[:300])); !errors.Is(e, media.ErrCapacity) {
		t.Fatal("staging budget overflow accepted", e)
	}
	_, e = h.s.CancelUpload(h.ctx, user, uA.UploadID, "cancel-ba")
	must(t, e)
	resumedB, e := h.s.AppendUpload(h.ctx, user, uB.UploadID, "bb-2", 0, bytes.NewReader(pB[:300]))
	must(t, e)
	if resumedB.UploadedBytes != 300 {
		t.Fatal("cancel did not release staging budget", resumedB.UploadedBytes)
	}
}

func TestRestartedUploadRevalidatesReplacementPrefix(t *testing.T) {
	h := newFixture(t)
	data := bytes.Repeat([]byte("valid text"), 100)
	v, err := h.s.CreateUpload(h.ctx, user, "restart-mime", request(data))
	must(t, err)
	first, err := h.s.AppendUpload(h.ctx, user, v.UploadID, "old", 0, bytes.NewReader(data[:600]))
	must(t, err)
	if !first.TypeValidated {
		t.Fatal("initial prefix was not validated")
	}
	must(t, h.s.Close(h.ctx))
	h.s, err = media.New(h.repo, h.policy, h.store, h.cfg)
	must(t, err)
	next, err := h.s.AppendUpload(h.ctx, user, v.UploadID, "fresh", 0, bytes.NewReader(data[:4]))
	must(t, err)
	if next.TypeValidated || next.UploadedBytes != 4 {
		t.Fatal("restarted prefix inherited validation", next.UploadedBytes)
	}
	next, err = h.s.AppendUpload(h.ctx, user, v.UploadID, "rest", 4, bytes.NewReader(data[4:]))
	must(t, err)
	if !next.TypeValidated || next.State != "awaiting_approval" {
		t.Fatal(next.State)
	}
}

type failingStatusStore struct {
	media.Store
	mu   sync.Mutex
	fail bool
}

func (s *failingStatusStore) Status(ctx context.Context, p media.Principal, id string) (storage.Status, error) {
	s.mu.Lock()
	fail := s.fail
	s.mu.Unlock()
	if fail {
		return storage.Status{}, storage.ErrUnavailable
	}
	return s.Store.Status(ctx, p, id)
}

func TestOperationsBacklogBlockedRetryBoundedPruneAndReadiness(t *testing.T) {
	h := newFixture(t)
	must(t, h.s.Close(h.ctx))

	var obsMu sync.Mutex
	var observations []media.Observation
	faultStore := &failingStatusStore{Store: h.store}
	cfg := h.cfg
	cfg.MaxAttempts = 1
	cfg.HistoryRetention = time.Hour
	cfg.Observer = media.ObserverFunc(func(_ context.Context, o media.Observation) {
		obsMu.Lock()
		observations = append(observations, o)
		obsMu.Unlock()
	})
	var e error
	h.s, e = media.New(h.repo, h.policy, faultStore, cfg)
	must(t, e)

	must(t, h.s.Readiness(h.ctx))
	if _, e = h.s.Operations(h.ctx, user, 10, ""); !errors.Is(e, media.ErrDenied) {
		t.Fatal("ordinary user accessed maintenance operations", e)
	}

	// Create an upload whose ingest response is lost so it enters verifying with a pending job.
	lostIngest := &lostStore{Store: faultStore, loseIngest: true}
	must(t, h.s.Close(h.ctx))
	h.s, e = media.New(h.repo, h.policy, lostIngest, cfg)
	must(t, e)

	data := []byte("blocked recovery job")
	v, e := h.s.CreateUpload(media.WithTraceID(h.ctx, "trace-ops-001"), user, "ops-create", request(data))
	must(t, e)
	if _, e = h.s.Upload(h.ctx, user, v.UploadID, "ops-upload", bytes.NewReader(data)); !errors.Is(e, media.ErrUnavailable) {
		t.Fatal("expected simulated lost ingest error", e)
	}

	// Now make storage.Status fail so RunOne exhausts MaxAttempts=1 and marks the job blocked,
	// and Readiness + GetVersion observe the storage degradation.
	faultStore.mu.Lock()
	faultStore.fail = true
	faultStore.mu.Unlock()
	if e = h.s.Readiness(h.ctx); !errors.Is(e, media.ErrUnavailable) {
		t.Fatal("expected Readiness failure when storage is unavailable", e)
	}
	degradedView, e := h.s.GetVersion(media.WithTraceID(h.ctx, "trace-status-deg"), user, v.ID)
	must(t, e)
	if degradedView.StorageState != "unavailable" {
		t.Fatalf("expected unavailable storage_state, got %s", degradedView.StorageState)
	}

	ran, e := h.s.RunOne(h.ctx, "ops-worker")
	if !ran || !errors.Is(e, media.ErrUnavailable) {
		t.Fatalf("expected failed RunOne attempt, ran=%v err=%v", ran, e)
	}

	h.clock.Add(10 * time.Second)
	ops, e := h.s.Operations(h.ctx, system, 10, "")
	must(t, e)
	if ops.Jobs.Blocked != 1 || len(ops.Failures) != 1 || ops.Failures[0].VersionID != v.ID || ops.Failures[0].State != "blocked" || ops.Outbox.Pending == 0 {
		t.Fatalf("unexpected operations snapshot: %+v", ops)
	}

	if _, e = h.s.RetryJob(h.ctx, system, v.ID, "wrong-gen", ops.Failures[0].Generation+1); !errors.Is(e, media.ErrConflict) {
		t.Fatal("accepted stale generation on RetryJob", e)
	}

	faultStore.mu.Lock()
	faultStore.fail = false
	faultStore.mu.Unlock()
	must(t, h.s.Readiness(h.ctx))

	retried, e := h.s.RetryJob(h.ctx, system, v.ID, "retry-valid", ops.Failures[0].Generation)
	must(t, e)
	if retried.State != "pending" || retried.Generation != ops.Failures[0].Generation+1 || retried.Attempts != 0 {
		t.Fatalf("unexpected retried job state: %+v", retried)
	}
	ran, e = h.s.RunOne(h.ctx, "ops-worker")
	must(t, e)
	if !ran {
		t.Fatal("expected retried job to run")
	}
	recovered, e := h.s.GetVersion(h.ctx, user, v.ID)
	must(t, e)
	if recovered.State != "awaiting_approval" {
		t.Fatalf("retried job did not recover version: %+v", recovered)
	}

	// Acknowledge 2 outbox events, leave remaining unacknowledged, advance past HistoryRetention, and prune.
	pendingEvents, e := h.repo.PendingEvents(h.ctx, 2)
	must(t, e)
	for _, ev := range pendingEvents {
		must(t, h.repo.AcknowledgeEvent(h.ctx, ev.ID))
	}
	var beforeAudit, beforeOutbox int
	must(t, h.db.QueryRow(`SELECT (SELECT count(*) FROM media.audit),(SELECT count(*) FROM media.outbox WHERE NOT delivered)`).Scan(&beforeAudit, &beforeOutbox))

	h.clock.Add(2 * time.Hour)
	early, e := h.s.Prune(h.ctx, 1)
	must(t, e)
	if early.DeletedReplays != 0 || early.DeletedEvents != 1 {
		t.Fatalf("manual pruning shortened replay window: %+v", early)
	}
	still, e := h.s.CreateUpload(h.ctx, user, "ops-create", request(data))
	must(t, e)
	if still.ID != v.ID {
		t.Fatal("prune changed replay before 24h", still.ID, v.ID)
	}
	h.clock.Add(23 * time.Hour)
	h.refreshQuota(t)
	// Both the version-ID reservation and the completed upload receipt must survive pruning.
	_, e = h.s.CreateUpload(h.ctx, user, "fresh-replay", request([]byte("fresh")))
	must(t, e)

	pruned1, e := h.s.Prune(h.ctx, 1)
	must(t, e)
	if pruned1.DeletedEvents != 1 || pruned1.DeletedReplays != 1 {
		t.Fatalf("bounded prune(1) expected 1 event & 1 replay, got %+v", pruned1)
	}
	prunedRest, e := h.s.Prune(h.ctx, 100)
	must(t, e)
	if prunedRest.DeletedEvents != 0 {
		t.Fatalf("expected all delivered events already pruned, got %+v", prunedRest)
	}

	var afterAudit, remainingFreshReplays, remainingUndelivered int
	must(t, h.db.QueryRow(`SELECT (SELECT count(*) FROM media.audit),(SELECT count(*) FROM media.replays),(SELECT count(*) FROM media.outbox WHERE NOT delivered)`).Scan(&afterAudit, &remainingFreshReplays, &remainingUndelivered))
	if afterAudit < beforeAudit || remainingFreshReplays != 2 || remainingUndelivered < beforeOutbox {
		t.Fatalf("prune touched audit, fresh replay, or undelivered outbox: audit=%d/%d replays=%d undelivered=%d/%d", afterAudit, beforeAudit, remainingFreshReplays, remainingUndelivered, beforeOutbox)
	}

	obsMu.Lock()
	foundStatusObs := false
	for _, o := range observations {
		if o.Operation == "media.storage.status" && o.ErrorCode == "media_unavailable" && o.TraceID == "trace-status-deg" {
			foundStatusObs = true
		}
	}
	obsMu.Unlock()
	if !foundStatusObs {
		t.Fatalf("missing sanitized storage status degradation observation: %+v", observations)
	}

	must(t, h.s.Close(h.ctx))
	if e = h.s.Readiness(h.ctx); !errors.Is(e, media.ErrUnavailable) {
		t.Fatal("closed service reported ready", e)
	}
}

func TestRetainedSourceSurvivesReleaseAndRestoresWithFreshPublication(t *testing.T) {
	h := newFixture(t)
	data := []byte("private source under review")
	v := h.ready(t, h.newUpload(t, "restore-source", data))
	keep := true
	var elapsed time.Duration
	h.cfg.Clock = func() time.Time { return h.clock.Now().Add(elapsed) }
	h.cfg.SourceRetention = func(ctx context.Context, module, id string) (bool, error) {
		return module == "fixture" && id == v.ID && keep, nil
	}
	service, err := media.New(h.repo, h.policy, h.store, h.cfg)
	must(t, err)
	defer service.Close(h.ctx)
	b := media.Binding{Module: "fixture", ResourceID: "proposal"}
	first, err := service.AttachPublication(h.ctx, user, v.ID, "first-attempt", b)
	must(t, err)
	_, err = service.Publish(h.ctx, user, first.ID, "publish-first")
	must(t, err)
	err = service.RetirePublication(h.ctx, user, v.ID, "block", b, "first-attempt")
	must(t, err)
	file, err := service.GetFile(h.ctx, user, v.FileID)
	must(t, err)
	if _, err := service.DeleteFile(h.ctx, user, v.FileID, "purge-retained", file.Revision); !errors.Is(err, media.ErrConflict) {
		t.Fatal("retained original could be deleted", err)
	}
	elapsed = 48 * time.Hour
	_, err = service.Sweep(h.ctx, 100, "")
	must(t, err)
	if err = service.Download(h.ctx, user, first.ID, io.Discard); !errors.Is(err, media.ErrDenied) {
		t.Fatal("released reference permitted access", err)
	}
	next, err := service.AttachPublication(h.ctx, user, v.ID, "restore-attempt", b)
	must(t, err)
	if next.ID == first.ID || next.ID != media.PublicationReferenceID(v.ID, b, "restore-attempt") {
		t.Fatal("restoration reused a retired reference")
	}
	_, err = service.Publish(h.ctx, user, next.ID, "publish-next")
	must(t, err)
	replay, err := service.AttachPublication(h.ctx, user, v.ID, "restore-attempt", b)
	if err != nil || replay.ID != next.ID {
		t.Fatal("publication replay lost binding", err)
	}
	var got bytes.Buffer
	must(t, service.Download(h.ctx, user, next.ID, &got))
	if !bytes.Equal(got.Bytes(), data) {
		t.Fatal("restored source differs")
	}
	keep = false
	_, err = service.Release(h.ctx, user, next.ID, "remove")
	must(t, err)
	current, err := service.GetVersion(h.ctx, user, v.ID)
	if err != nil || current.State != "deleting" {
		t.Fatal("removed source did not enter cleanup", current.State, err)
	}
}

func (h *fixture) refreshQuota(t *testing.T) {
	t.Helper()
	items, err := h.store.Instances(h.ctx, system, 100, "")
	must(t, err)
	for _, i := range items {
		must(t, h.store.RefreshInstance(h.ctx, system, i.ID))
	}
}

func TestAdmissionRejectsBeforeSessionAndSameRequestResumes(t *testing.T) {
	h := newFixture(t)
	list, err := h.store.Instances(h.ctx, system, 100, "")
	must(t, err)
	var paused []storage.InstanceHealth
	for _, i := range list {
		r, e := h.store.CommandInstance(h.ctx, system, i.ID, "pause-"+i.ID, storage.InstanceCommand{Revision: i.Revision, Action: "pause"})
		must(t, e)
		paused = append(paused, r)
	}
	data := []byte("resume once")
	state, err := h.s.UploadIntake(h.ctx, user, "documents", int64(len(data)))
	must(t, err)
	if state.Mode != "paused" || state.Reason != "storage_replica_shortage" {
		t.Fatal(state)
	}
	if _, err = h.s.CreateUpload(h.ctx, user, "admission", request(data)); !errors.Is(err, media.ErrReplicaShortage) {
		t.Fatal("session admitted without replicas", err)
	}
	var files, versions int
	must(t, h.db.QueryRow("SELECT (SELECT count(*) FROM media.files),(SELECT count(*) FROM media.versions)").Scan(&files, &versions))
	if files != 0 || versions != 0 || totalWrites(h) != 0 {
		t.Fatal("rejected upload changed files, versions or physical data")
	}
	for _, r := range paused {
		_, err = h.store.CommandInstance(h.ctx, system, r.ID, "resume-"+r.ID, storage.InstanceCommand{Revision: r.Revision, Action: "resume"})
		must(t, err)
	}
	v, err := h.s.CreateUpload(h.ctx, user, "admission", request(data))
	must(t, err)
	again, err := h.s.CreateUpload(h.ctx, user, "admission", request(data))
	must(t, err)
	if again.ID != v.ID || again.UploadID != v.UploadID || v.UploadID == "" {
		t.Fatal("recovery did not reuse the accepted upload")
	}
}
