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
	"io"
	"os"
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
	mu     sync.Mutex
	files  map[string][]byte
	writes map[string]int
	hook   func()
}

func (p *provider) Verify(_ context.Context, i storage.Instance) (storage.InstanceEvidence, error) {
	return storage.InstanceEvidence{AccountDomain: "fixture:" + i.ID, ProviderFree: 1 << 20, VerifiedAt: time.Now()}, nil
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
	var random [8]byte
	_, e = rand.Read(random[:])
	must(t, e)
	name := "media_test_" + hex.EncodeToString(random[:])
	mediaRole := name + "_media"
	storageRole := name + "_storage"
	_, e = control.Exec(`CREATE DATABASE ` + name)
	must(t, e)
	admin, e := sql.Open("pgx", dsn+" dbname="+name)
	must(t, e)
	_, e = admin.Exec(mp.Schema + sp.Schema)
	must(t, e)
	_, e = admin.Exec(fmt.Sprintf(`CREATE ROLE %s LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE; CREATE ROLE %s LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE;
 GRANT USAGE ON SCHEMA media TO %s; GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA media TO %s; REVOKE UPDATE,DELETE ON media.audit FROM %s;
 GRANT USAGE ON SCHEMA storage TO %s; GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA storage TO %s; REVOKE UPDATE,DELETE ON storage.audit FROM %s;
 REVOKE ALL ON SCHEMA public FROM PUBLIC;`, mediaRole, storageRole, mediaRole, mediaRole, mediaRole, storageRole, storageRole, storageRole))
	must(t, e)
	db, e := sql.Open("pgx", dsn+" dbname="+name+" user="+mediaRole)
	must(t, e)
	db.SetMaxOpenConns(12)
	storageDB, e := sql.Open("pgx", dsn+" dbname="+name+" user="+storageRole)
	must(t, e)
	storageDB.SetMaxOpenConns(12)
	c := &clock{t: time.Now().UTC()}
	p := &provider{files: map[string][]byte{}, writes: map[string]int{}}
	sr := &sp.Repository{DB: storageDB}
	must(t, sr.CheckRuntime(context.Background()))
	st, e := storage.New(sr, storagePolicy{}, p, p, storage.Config{Clock: c.Now, MaxObjectSize: 1 << 20, TemporaryDirectory: t.TempDir(), ParallelTransfers: 4, Lease: time.Minute, VerificationAge: time.Hour, MaxAttempts: 3})
	must(t, e)
	a := &policy{denied: map[string]bool{}}
	repo := &mp.Repository{DB: db}
	must(t, repo.CheckRuntime(context.Background()))
	cfg := media.Config{Profiles: map[string]media.Profile{"documents": {Module: "fixture", Quarantine: media.Protection{Class: "quarantine", Scope: "school"}, Published: media.Protection{Class: "public", Scope: "school", Public: true}, AllowedTypes: []string{"text/plain", "application/pdf"}, MaxSize: 1 << 20}}, Actor: system, Clock: c.Now, UploadTTL: 15 * time.Minute, UnreferencedTTL: time.Hour, OperationTimeout: time.Minute, ParallelTransfers: 4, MaxOpenUploads: 10, MaxFilesPerOwner: 100, MaxVersions: 10, MaxReferences: 10, MaxAttempts: 3}
	s, e := media.New(repo, a, st, cfg)
	must(t, e)
	h := &fixture{s, st, repo, db, admin, p, a, c, cfg, context.Background()}
	t.Cleanup(func() {
		_ = h.s.Close(context.Background())
		_ = st.Close(context.Background())
		db.Close()
		storageDB.Close()
		admin.Close()
		_, e := control.Exec(`DROP DATABASE ` + name + ` WITH (FORCE)`)
		if e != nil {
			t.Error(e)
		}
		_, e = control.Exec(`DROP ROLE ` + mediaRole + `, ` + storageRole)
		if e != nil {
			t.Error(e)
		}
		control.Close()
	})
	for n := 0; n < 3; n++ {
		id := fmt.Sprintf("account-%d", n)
		admissions := []storage.Admission{{Class: "public", Scope: "school", Plaintext: true, ExpiresAt: c.Now().Add(48 * time.Hour)}}
		kind := "contributor"
		if n == 0 {
			kind = "platform"
			admissions = append(admissions, storage.Admission{Class: "quarantine", Scope: "school", Plaintext: true, ExpiresAt: c.Now().Add(48 * time.Hour)})
		}
		_, e = st.Register(h.ctx, system, "register-"+id, storage.Instance{ID: id, Adapter: "fixture", OwnerDomain: id, Ownership: kind, CredentialRef: id, CredentialRevision: 1, Root: "isolated", State: "active", Authorized: true, Limit: 1 << 20, ExpiresAt: c.Now().Add(48 * time.Hour), Admissions: admissions})
		must(t, e)
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
	if h.provider.writes["account-1"] != 0 || h.provider.writes["account-2"] != 0 {
		t.Error("unapproved bytes reached contributor accounts")
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
	if _, e = h.s.Upload(h.ctx, user, v.UploadID, "bytes", bytes.NewReader(data)); !errors.Is(e, media.ErrUnavailable) {
		t.Fatal(e)
	}
	h.clock.Add(25 * time.Hour)
	_, e = h.store.Reconcile(h.ctx, system, 100, "")
	must(t, e)
	h.cycle(t)
	st, e := h.s.GetVersion(h.ctx, user, v.ID)
	must(t, e)
	if st.State != "expired" || !st.CleanupComplete {
		t.Fatal(st.State, st.CleanupComplete)
	}
	var count int
	must(t, h.admin.QueryRow(`SELECT count(*) FROM storage.objects`).Scan(&count))
	if count != 1 {
		t.Fatal("created replacement object while recovering", count)
	}
}
