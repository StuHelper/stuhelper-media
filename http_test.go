package media_test

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	media "github.com/StuHelper/stuhelper-media"
	"github.com/StuHelper/stuhelper-media/httpapi"
	"github.com/StuHelper/stuhelper-media/sdk"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type authenticate struct{}

func (authenticate) Authenticate(r *http.Request) (media.Principal, error) {
	switch r.Header.Get("Authorization") {
	case "Bearer fixture-owner":
		return user, nil
	case "Bearer auth-outage":
		return media.Principal{}, media.ErrUnavailable
	default:
		return media.Principal{}, media.ErrDenied
	}
}

type proofContextKey struct{}
type proofFixture struct {
	authenticate
	media.Authorizer
}

func (p proofFixture) Authenticate(r *http.Request) (media.Principal, error) {
	actor, err := p.authenticate.Authenticate(r)
	if err == nil {
		*r = *r.WithContext(context.WithValue(r.Context(), proofContextKey{}, actor))
	}
	return actor, err
}
func (p proofFixture) Authorize(ctx context.Context, actor media.Principal, action string, a media.Access) error {
	if ctx.Value(proofContextKey{}) != actor {
		return media.ErrDenied
	}
	return p.Authorizer.Authorize(ctx, actor, action, a)
}

func TestHTTPGeneratedSDKRejectsUntrustedFieldsAndProtectsContent(t *testing.T) {
	h := newFixture(t)
	t.Run("authenticated request context reaches service", func(t *testing.T) {
		auth := proofFixture{authenticate{}, h.policy}
		svc, err := media.New(h.repo, auth, h.store, h.cfg)
		must(t, err)
		defer svc.Close(h.ctx)
		handler, err := httpapi.New(svc, auth, 1024)
		must(t, err)
		req := httptest.NewRequest("POST", "/api/v1/media/uploads", bytes.NewReader(mustJSON(t, request([]byte("fixture")))))
		req.Header.Set("Authorization", "Bearer fixture-owner")
		req.Header.Set("Idempotency-Key", "proof")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatal(w.Code, w.Body.String())
		}
	})
	handler, e := httpapi.New(h.s, authenticate{}, 1<<20)
	must(t, e)
	server := httptest.NewServer(handler)
	defer server.Close()
	client, e := sdk.NewClientWithResponses(server.URL, sdk.WithRequestEditorFn(func(_ context.Context, r *http.Request) error {
		r.Header.Set("Authorization", "Bearer fixture-owner")
		return nil
	}))
	must(t, e)
	data := []byte("contract upload")
	r := request(data)
	created, e := client.CreateUploadWithResponse(h.ctx, &sdk.CreateUploadParams{IdempotencyKey: "sdk-create"}, sdk.UploadRequest{Purpose: r.Purpose, Filename: r.Filename, ContentType: r.ContentType, Size: r.Size, Sha256: r.SHA256})
	must(t, e)
	if created.StatusCode() != 200 || created.JSON200 == nil {
		t.Fatal(created.StatusCode(), string(created.Body))
	}
	v := created.JSON200
	uploaded, e := client.UploadContentWithBodyWithResponse(h.ctx, v.UploadId, &sdk.UploadContentParams{IdempotencyKey: "sdk-bytes"}, "application/octet-stream", bytes.NewReader(data))
	must(t, e)
	if uploaded.StatusCode() != 200 {
		t.Fatal(uploaded.StatusCode(), string(uploaded.Body))
	}
	status, e := h.s.GetVersion(h.ctx, user, v.Id)
	must(t, e)
	ready := h.ready(t, status.Version)
	ref := h.bind(t, ready, "sdk")
	response, e := client.DownloadReference(h.ctx, ref.ID)
	must(t, e)
	body, e := io.ReadAll(response.Body)
	response.Body.Close()
	must(t, e)
	if response.StatusCode != 200 || !bytes.Equal(body, data) {
		t.Fatal(response.StatusCode, string(body))
	}
	_, params, e := mime.ParseMediaType(response.Header.Get("Content-Disposition"))
	must(t, e)
	if params["filename"] != r.Filename || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("unsafe download headers")
	}
	raw, e := json.Marshal(status)
	must(t, e)
	for _, secret := range []string{"object_id", "profile", "account-", "credential", "gns://"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("storage metadata exposed", secret)
		}
	}
	unauth, e := http.Get(server.URL + "/api/v1/media/uploads/" + v.UploadId)
	must(t, e)
	unauth.Body.Close()
	if unauth.StatusCode != 401 {
		t.Fatal(unauth.StatusCode)
	}
	malicious := strings.Replace(string(mustJSON(t, r)), "{", `{"protection":{"public":true},`, 1)
	req, e := http.NewRequest("POST", server.URL+"/api/v1/media/uploads", strings.NewReader(malicious))
	must(t, e)
	req.Header.Set("Authorization", "Bearer fixture-owner")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "untrusted-protection")
	denied, e := http.DefaultClient.Do(req)
	must(t, e)
	denied.Body.Close()
	if denied.StatusCode != 400 {
		t.Fatal("accepted client classification", denied.StatusCode)
	}
	h.policy.deny("media.references.download", true)
	denied, e = client.DownloadReference(h.ctx, ref.ID)
	must(t, e)
	defer denied.Body.Close()
	b, e := io.ReadAll(denied.Body)
	must(t, e)
	if denied.StatusCode != 403 || bytes.Contains(b, data) || denied.Header.Get("Content-Disposition") != "" {
		t.Fatal("denial leaked content", denied.StatusCode)
	}
}

func TestHTTPReuseLifecycleArchiveAbortAndPayloadLimits(t *testing.T) {
	h := newFixture(t)
	handler, e := httpapi.New(h.s, authenticate{}, 1024)
	must(t, e)
	server := httptest.NewServer(handler)
	defer server.Close()
	client, e := sdk.NewClientWithResponses(server.URL, sdk.WithRequestEditorFn(func(_ context.Context, r *http.Request) error {
		r.Header.Set("Authorization", "Bearer fixture-owner")
		return nil
	}))
	must(t, e)

	// 1. Upload first file via HTTP SDK, approve, attach, publish, and reuse_existing recovery/cancel.
	firstBytes := []byte("first reusable lecture notes")
	r1 := request(firstBytes)
	c1, e := client.CreateUploadWithResponse(h.ctx, &sdk.CreateUploadParams{IdempotencyKey: "http-c1"}, sdk.UploadRequest{
		Purpose: r1.Purpose, Filename: r1.Filename, ContentType: r1.ContentType, Size: r1.Size, Sha256: r1.SHA256,
	})
	must(t, e)
	if c1.StatusCode() != 200 || c1.JSON200 == nil {
		t.Fatal(c1.StatusCode(), string(c1.Body))
	}
	u1, e := client.UploadContentWithBodyWithResponse(h.ctx, c1.JSON200.UploadId, &sdk.UploadContentParams{IdempotencyKey: "http-u1"}, "application/octet-stream", bytes.NewReader(firstBytes))
	must(t, e)
	if u1.StatusCode() != 200 || u1.JSON200 == nil || u1.JSON200.State != "awaiting_approval" {
		t.Fatal(u1.StatusCode(), string(u1.Body))
	}
	a1, e := client.ApproveVersionWithResponse(h.ctx, c1.JSON200.Id, &sdk.ApproveVersionParams{IdempotencyKey: "http-a1"})
	must(t, e)
	if a1.StatusCode() != 200 || a1.JSON200 == nil || !a1.JSON200.Approved {
		t.Fatal(a1.StatusCode(), string(a1.Body))
	}
	for n := 0; n < 8; n++ {
		h.cycle(t)
		gv, err := client.GetVersionWithResponse(h.ctx, c1.JSON200.Id)
		must(t, err)
		if gv.StatusCode() == 200 && gv.JSON200 != nil && gv.JSON200.State == "ready" && gv.JSON200.Healthy == 3 {
			break
		}
	}
	att1, e := client.AttachReferenceWithResponse(h.ctx, c1.JSON200.Id, &sdk.AttachReferenceParams{IdempotencyKey: "http-att1"}, sdk.Binding{Module: "fixture", ResourceId: "course-1"})
	must(t, e)
	if att1.StatusCode() != 200 || att1.JSON200 == nil {
		t.Fatal(att1.StatusCode(), string(att1.Body))
	}
	pub1, e := client.PublishReferenceWithResponse(h.ctx, att1.JSON200.Id, &sdk.PublishReferenceParams{IdempotencyKey: "http-pub1"})
	must(t, e)
	if pub1.StatusCode() != 200 || pub1.JSON200 == nil || pub1.JSON200.State != "active" {
		t.Fatal(pub1.StatusCode(), string(pub1.Body))
	}

	reuseTrue := true
	reused, e := client.CreateUploadWithResponse(h.ctx, &sdk.CreateUploadParams{IdempotencyKey: "http-reuse"}, sdk.UploadRequest{
		Purpose: r1.Purpose, Filename: "复用讲义.txt", ContentType: r1.ContentType, Size: r1.Size, Sha256: r1.SHA256, ReuseExisting: &reuseTrue,
	})
	must(t, e)
	if reused.StatusCode() != 200 || reused.JSON200 == nil || reused.JSON200.Reused == nil || !*reused.JSON200.Reused || reused.JSON200.State != "awaiting_approval" {
		t.Fatal(reused.StatusCode(), string(reused.Body))
	}
	replayReuse, e := client.CreateUploadWithResponse(h.ctx, &sdk.CreateUploadParams{IdempotencyKey: "http-reuse"}, sdk.UploadRequest{
		Purpose: r1.Purpose, Filename: "复用讲义.txt", ContentType: r1.ContentType, Size: r1.Size, Sha256: r1.SHA256, ReuseExisting: &reuseTrue,
	})
	must(t, e)
	if replayReuse.StatusCode() != 200 || replayReuse.JSON200 == nil || replayReuse.JSON200.Id != reused.JSON200.Id {
		t.Fatal("reuse replay diverged", replayReuse.StatusCode(), string(replayReuse.Body))
	}
	polled, e := client.GetUploadWithResponse(h.ctx, reused.JSON200.UploadId)
	must(t, e)
	if polled.StatusCode() != 200 || polled.JSON200 == nil || polled.JSON200.State != "awaiting_approval" {
		t.Fatal(polled.StatusCode(), string(polled.Body))
	}
	cancelled, e := client.CancelUploadWithResponse(h.ctx, reused.JSON200.UploadId, &sdk.CancelUploadParams{IdempotencyKey: "http-cancel-reuse"})
	must(t, e)
	if cancelled.StatusCode() != 200 || cancelled.JSON200 == nil || cancelled.JSON200.State != "cancelled" {
		t.Fatal(cancelled.StatusCode(), string(cancelled.Body))
	}

	// 2. Oversized HTTP 413 payload limits on binary upload (max=1024) and JSON body (>65536).
	largeData := bytes.Repeat([]byte("A"), 2048)
	rLarge := request(largeData)
	cLarge, e := client.CreateUploadWithResponse(h.ctx, &sdk.CreateUploadParams{IdempotencyKey: "http-large-meta"}, sdk.UploadRequest{
		Purpose: rLarge.Purpose, Filename: rLarge.Filename, ContentType: rLarge.ContentType, Size: rLarge.Size, Sha256: rLarge.SHA256,
	})
	must(t, e)
	if cLarge.StatusCode() != 200 || cLarge.JSON200 == nil {
		t.Fatal(cLarge.StatusCode(), string(cLarge.Body))
	}
	tooLargeKnown, e := client.UploadContentWithBodyWithResponse(h.ctx, cLarge.JSON200.UploadId, &sdk.UploadContentParams{IdempotencyKey: "http-large-known"}, "application/octet-stream", bytes.NewReader(largeData))
	must(t, e)
	if tooLargeKnown.StatusCode() != 413 || tooLargeKnown.JSON413 == nil || tooLargeKnown.JSON413.Code != "media_upload_too_large" {
		t.Fatal("expected 413 for known-length oversized upload", tooLargeKnown.StatusCode(), string(tooLargeKnown.Body))
	}
	chunkedReq, e := http.NewRequest("PUT", server.URL+"/api/v1/media/uploads/"+cLarge.JSON200.UploadId+"/content", io.NopCloser(bytes.NewReader(largeData)))
	must(t, e)
	chunkedReq.ContentLength = -1
	chunkedReq.Header.Set("Authorization", "Bearer fixture-owner")
	chunkedReq.Header.Set("Content-Type", "application/octet-stream")
	chunkedReq.Header.Set("Idempotency-Key", "http-large-chunked")
	chunkedResp, e := http.DefaultClient.Do(chunkedReq)
	must(t, e)
	chunkedBody, _ := io.ReadAll(chunkedResp.Body)
	chunkedResp.Body.Close()
	if chunkedResp.StatusCode != 413 || !bytes.Contains(chunkedBody, []byte("media_upload_too_large")) {
		t.Fatal("expected 413 for chunked oversized upload", chunkedResp.StatusCode, string(chunkedBody))
	}

	hugeJSON := `{"purpose":"documents","filename":"` + strings.Repeat("x", 70000) + `"}`
	jsonChunkedReq, e := http.NewRequest("POST", server.URL+"/api/v1/media/uploads", io.NopCloser(strings.NewReader(hugeJSON)))
	must(t, e)
	jsonChunkedReq.ContentLength = -1
	jsonChunkedReq.Header.Set("Authorization", "Bearer fixture-owner")
	jsonChunkedReq.Header.Set("Content-Type", "application/json")
	jsonChunkedReq.Header.Set("Idempotency-Key", "http-huge-json")
	jsonChunkedResp, e := http.DefaultClient.Do(jsonChunkedReq)
	must(t, e)
	jsonChunkedBody, _ := io.ReadAll(jsonChunkedResp.Body)
	jsonChunkedResp.Body.Close()
	if jsonChunkedResp.StatusCode != 413 || !bytes.Contains(jsonChunkedBody, []byte("media_upload_too_large")) {
		t.Fatal("expected 413 for oversized JSON body", jsonChunkedResp.StatusCode, string(jsonChunkedBody))
	}

	// 3. Archive manifest, ZIP download, and mid-archive revocation stream abort.
	secondBytes := []byte("CONFIDENTIAL_SECOND_ARCHIVE_ENTRY")
	v2 := h.ready(t, h.newUpload(t, "http-second", secondBytes))
	ref2 := h.bind(t, v2, "course-2")
	refs := []string{pub1.JSON200.Id, ref2.ID}

	manifest, e := client.ArchiveManifestWithResponse(h.ctx, sdk.ArchiveRequest{References: refs})
	must(t, e)
	if manifest.StatusCode() != 200 || manifest.JSON200 == nil || len(manifest.JSON200.Entries) != 2 {
		t.Fatal(manifest.StatusCode(), string(manifest.Body))
	}
	archOK, e := client.DownloadArchive(h.ctx, sdk.ArchiveRequest{References: refs})
	must(t, e)
	zipBytes, e := io.ReadAll(archOK.Body)
	archOK.Body.Close()
	must(t, e)
	if archOK.StatusCode != 200 {
		t.Fatal(archOK.StatusCode, string(zipBytes))
	}
	zr, e := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	must(t, e)
	if len(zr.File) != 3 {
		t.Fatal("unexpected zip entry count", len(zr.File))
	}

	// Arm a 2-step hook: allow 1st entry to flush HTTP 200 + bytes, then revoke permission on 2nd entry read.
	h.provider.mu.Lock()
	h.provider.hook = func() {
		h.provider.mu.Lock()
		h.provider.hook = func() {
			h.policy.deny("media.references.download", true)
		}
		h.provider.mu.Unlock()
	}
	h.provider.mu.Unlock()
	abortedResp, abortErr := client.DownloadArchive(h.ctx, sdk.ArchiveRequest{References: refs})
	if abortErr == nil {
		partial, readErr := io.ReadAll(abortedResp.Body)
		abortedResp.Body.Close()
		if bytes.Contains(partial, secondBytes) {
			t.Fatal("mid-archive revocation leaked second entry bytes")
		}
		_, zipErr := zip.NewReader(bytes.NewReader(partial), int64(len(partial)))
		if readErr == nil && zipErr == nil {
			t.Fatal("expected aborted incomplete stream after mid-archive revocation")
		}
	}
	h.policy.deny("media.references.download", false)

	// 4. Auth 503 vs 401, nil body safety, invalid headers/query/body, file state & delete lifecycle.
	outageReq, e := http.NewRequest("GET", server.URL+"/api/v1/media/files", nil)
	must(t, e)
	outageReq.Header.Set("Authorization", "Bearer auth-outage")
	outageResp, e := http.DefaultClient.Do(outageReq)
	must(t, e)
	outageResp.Body.Close()
	if outageResp.StatusCode != 503 {
		t.Fatal("expected 503 on auth outage", outageResp.StatusCode)
	}

	nilBodyReq := httptest.NewRequest("POST", "/api/v1/media/versions/"+c1.JSON200.Id+"/approval", nil)
	nilBodyReq.Header.Set("Authorization", "Bearer fixture-owner")
	nilBodyReq.Header.Set("Idempotency-Key", "nil-body-approve")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, nilBodyReq)
	if rec.Code != 200 {
		t.Fatal("nil request body failed", rec.Code, rec.Body.String())
	}

	dupHeaderReq, e := http.NewRequest("POST", server.URL+"/api/v1/media/versions/"+c1.JSON200.Id+"/approval", nil)
	must(t, e)
	dupHeaderReq.Header.Set("Authorization", "Bearer fixture-owner")
	dupHeaderReq.Header.Add("Idempotency-Key", "k1")
	dupHeaderReq.Header.Add("Idempotency-Key", "k2")
	dupResp, e := http.DefaultClient.Do(dupHeaderReq)
	must(t, e)
	dupResp.Body.Close()
	if dupResp.StatusCode != 400 {
		t.Fatal("duplicate Idempotency-Key accepted", dupResp.StatusCode)
	}

	badQueryReq, e := http.NewRequest("GET", server.URL+"/api/v1/media/files?unknown=1", nil)
	must(t, e)
	badQueryReq.Header.Set("Authorization", "Bearer fixture-owner")
	badQueryResp, e := http.DefaultClient.Do(badQueryReq)
	must(t, e)
	badQueryResp.Body.Close()
	if badQueryResp.StatusCode != 400 {
		t.Fatal("unknown query parameter accepted", badQueryResp.StatusCode)
	}

	fileView, e := client.GetFileWithResponse(h.ctx, c1.JSON200.FileId)
	must(t, e)
	if fileView.StatusCode() != 200 || fileView.JSON200 == nil {
		t.Fatal(fileView.StatusCode(), string(fileView.Body))
	}
	disabledFile, e := client.SetFileStateWithResponse(h.ctx, fileView.JSON200.Id, &sdk.SetFileStateParams{IdempotencyKey: "http-disable"}, sdk.FileState{Revision: fileView.JSON200.Revision, Disabled: true})
	must(t, e)
	if disabledFile.StatusCode() != 200 || disabledFile.JSON200 == nil || !disabledFile.JSON200.Disabled {
		t.Fatal(disabledFile.StatusCode(), string(disabledFile.Body))
	}
	reEnabled, e := client.SetFileStateWithResponse(h.ctx, fileView.JSON200.Id, &sdk.SetFileStateParams{IdempotencyKey: "http-enable"}, sdk.FileState{Revision: disabledFile.JSON200.Revision, Disabled: false})
	must(t, e)
	if reEnabled.StatusCode() != 200 || reEnabled.JSON200 == nil || reEnabled.JSON200.Disabled {
		t.Fatal(reEnabled.StatusCode(), string(reEnabled.Body))
	}
	delConflict, e := client.DeleteFileWithResponse(h.ctx, fileView.JSON200.Id, &sdk.DeleteFileParams{IdempotencyKey: "http-del-conflict"}, sdk.Revision{Revision: reEnabled.JSON200.Revision})
	must(t, e)
	if delConflict.StatusCode() != 409 {
		t.Fatal("expected 409 deleting file with active reference", delConflict.StatusCode())
	}
	rel, e := client.ReleaseReferenceWithResponse(h.ctx, pub1.JSON200.Id, &sdk.ReleaseReferenceParams{IdempotencyKey: "http-rel-1"})
	must(t, e)
	if rel.StatusCode() != 200 || rel.JSON200 == nil || rel.JSON200.State != "released" {
		t.Fatal(rel.StatusCode(), string(rel.Body))
	}
	freshFile, e := client.GetFileWithResponse(h.ctx, fileView.JSON200.Id)
	must(t, e)
	delOK, e := client.DeleteFileWithResponse(h.ctx, fileView.JSON200.Id, &sdk.DeleteFileParams{IdempotencyKey: "http-del-ok"}, sdk.Revision{Revision: freshFile.JSON200.Revision})
	must(t, e)
	if delOK.StatusCode() != 200 || delOK.JSON200 == nil || !delOK.JSON200.Deleting {
		t.Fatal(delOK.StatusCode(), string(delOK.Body))
	}
}

func TestCheckWithPostgresScriptBinaryResolution(t *testing.T) {
	writeExec := func(dir, name, content string) {
		t.Helper()
		p := filepath.Join(dir, name)
		must(t, os.WriteFile(p, []byte("#!/usr/bin/env bash\nset -euo pipefail\n"+content+"\n"), 0o755))
	}
	setupMockServer := func(pgDir, markerFile string) {
		writeExec(pgDir, "postgres", `echo "postgres (PostgreSQL) 18.6-mock"`)
		writeExec(pgDir, "initdb", `mkdir -p "$2"`)
		writeExec(pgDir, "pg_ctl", `true`)
		writeExec(pgDir, "make", `printf '%s' "$STUHELPER_TEST_PG_BIN" > "`+markerFile+`"`)
	}

	// Case 1: Resolved via pg_config --bindir when STUHELPER_TEST_PG_BIN is unset.
	dir1 := t.TempDir()
	pgBindir1 := filepath.Join(dir1, "opt-pg-bin")
	must(t, os.MkdirAll(pgBindir1, 0o755))
	marker1 := filepath.Join(dir1, "resolved.txt")
	setupMockServer(pgBindir1, marker1)
	toolDir1 := filepath.Join(dir1, "tools")
	must(t, os.MkdirAll(toolDir1, 0o755))
	writeExec(toolDir1, "pg_config", `echo "`+pgBindir1+`"`)
	writeExec(toolDir1, "make", `printf '%s' "$STUHELPER_TEST_PG_BIN" > "`+marker1+`"`)

	cmd1 := exec.Command("bash", "scripts/check-with-postgres.sh")
	cmd1.Env = []string{
		"PATH=" + toolDir1 + ":/usr/bin:/bin",
		"HOME=" + dir1,
	}
	if out, e := cmd1.CombinedOutput(); e != nil {
		t.Fatalf("pg_config resolution failed: %v\n%s", e, string(out))
	}
	got1, e := os.ReadFile(marker1)
	must(t, e)
	if string(got1) != pgBindir1 {
		t.Fatalf("expected %q, got %q", pgBindir1, string(got1))
	}

	// Case 2: pg_config points to client-only dir without initdb; falls back to dirname $(command -v initdb).
	dir2 := t.TempDir()
	clientOnly := filepath.Join(dir2, "client-only")
	must(t, os.MkdirAll(clientOnly, 0o755))
	pgBindir2 := filepath.Join(dir2, "fallback-initdb-bin")
	must(t, os.MkdirAll(pgBindir2, 0o755))
	marker2 := filepath.Join(dir2, "resolved2.txt")
	setupMockServer(pgBindir2, marker2)
	writeExec(clientOnly, "pg_config", `echo "`+clientOnly+`"`)

	cmd2 := exec.Command("bash", "scripts/check-with-postgres.sh")
	cmd2.Env = []string{
		"PATH=" + clientOnly + ":" + pgBindir2 + ":/usr/bin:/bin",
		"HOME=" + dir2,
	}
	if out, e := cmd2.CombinedOutput(); e != nil {
		t.Fatalf("initdb PATH fallback failed: %v\n%s", e, string(out))
	}
	got2, e := os.ReadFile(marker2)
	must(t, e)
	if string(got2) != pgBindir2 {
		t.Fatalf("expected %q, got %q", pgBindir2, string(got2))
	}
}

type blockingReader struct {
	source  io.Reader
	entered chan struct{}
	release chan struct{}
}

func (r *blockingReader) Read(p []byte) (int, error) {
	select {
	case <-r.entered:
	default:
		close(r.entered)
	}
	<-r.release
	return r.source.Read(p)
}

func TestHTTPStructuredErrorCodesLimitsAndRetryAfter(t *testing.T) {
	h := newFixture(t)
	must(t, h.s.Close(h.ctx))
	cfg := h.cfg
	cfg.ParallelTransfers = 1
	cfg.MaxOpenUploads = 1
	cfg.MaxFilesPerOwner = 2
	cfg.MaxVersions = 1
	cfg.MaxReferences = 1
	cfg.MaxArchiveBytes = 5
	cfg.Profiles = map[string]media.Profile{
		"documents": {
			Module:       "fixture",
			Quarantine:   h.cfg.Profiles["documents"].Quarantine,
			Published:    h.cfg.Profiles["documents"].Published,
			AllowedTypes: []string{"text/plain"},
			MaxSize:      100,
		},
	}
	var e error
	h.s, e = media.New(h.repo, h.policy, h.store, cfg)
	must(t, e)

	handler, e := httpapi.New(h.s, authenticate{}, 200)
	must(t, e)
	server := httptest.NewServer(handler)
	defer server.Close()
	client, e := sdk.NewClientWithResponses(server.URL, sdk.WithRequestEditorFn(func(_ context.Context, r *http.Request) error {
		r.Header.Set("Authorization", "Bearer fixture-owner")
		return nil
	}))
	must(t, e)

	// 1. Filename & MIME type & upload size sub-errors (preserving errors.Is(..., ErrInput)).
	badName := request([]byte("ok"))
	badName.Filename = "bad/name.txt"
	if _, err := h.s.CreateUpload(h.ctx, user, "svc-bad-name", badName); !errors.Is(err, media.ErrFilenameInvalid) || !errors.Is(err, media.ErrInput) {
		t.Fatalf("expected ErrFilenameInvalid wrapping ErrInput, got %v", err)
	}
	resName, e := client.CreateUploadWithResponse(h.ctx, &sdk.CreateUploadParams{IdempotencyKey: "http-bad-name"}, sdk.UploadRequest{
		Purpose: badName.Purpose, Filename: badName.Filename, ContentType: badName.ContentType, Size: badName.Size, Sha256: badName.SHA256,
	})
	must(t, e)
	if resName.StatusCode() != 400 || resName.JSON400 == nil || resName.JSON400.Code != sdk.ProblemCodeMediaFilenameInvalid {
		t.Fatalf("unexpected filename invalid response: %d %s", resName.StatusCode(), string(resName.Body))
	}

	badType := request([]byte("ok"))
	badType.ContentType = "application/zip"
	resType, e := client.CreateUploadWithResponse(h.ctx, &sdk.CreateUploadParams{IdempotencyKey: "http-bad-type"}, sdk.UploadRequest{
		Purpose: badType.Purpose, Filename: badType.Filename, ContentType: badType.ContentType, Size: badType.Size, Sha256: badType.SHA256,
	})
	must(t, e)
	if resType.StatusCode() != 400 || resType.JSON400 == nil || resType.JSON400.Code != sdk.ProblemCodeMediaTypeNotAllowed {
		t.Fatalf("unexpected type not allowed response: %d %s", resType.StatusCode(), string(resType.Body))
	}

	tooBig := request(bytes.Repeat([]byte("x"), 101))
	resBig, e := client.CreateUploadWithResponse(h.ctx, &sdk.CreateUploadParams{IdempotencyKey: "http-too-big"}, sdk.UploadRequest{
		Purpose: tooBig.Purpose, Filename: tooBig.Filename, ContentType: tooBig.ContentType, Size: tooBig.Size, Sha256: tooBig.SHA256,
	})
	must(t, e)
	if resBig.StatusCode() != 413 || resBig.JSON413 == nil || resBig.JSON413.Code != sdk.ProblemCodeMediaUploadTooLarge || resBig.JSON413.Limit == nil || *resBig.JSON413.Limit != 100 {
		t.Fatalf("unexpected upload too large response: %d %s", resBig.StatusCode(), string(resBig.Body))
	}

	// 2. Open uploads limit -> 429 with limit=1.
	firstData := []byte("first file content")
	firstReq := request(firstData)
	u1, e := client.CreateUploadWithResponse(h.ctx, &sdk.CreateUploadParams{IdempotencyKey: "u1"}, sdk.UploadRequest{
		Purpose: firstReq.Purpose, Filename: firstReq.Filename, ContentType: firstReq.ContentType, Size: firstReq.Size, Sha256: firstReq.SHA256,
	})
	must(t, e)
	openLimited, e := client.CreateUploadWithResponse(h.ctx, &sdk.CreateUploadParams{IdempotencyKey: "u2-open-limit"}, sdk.UploadRequest{
		Purpose: firstReq.Purpose, Filename: firstReq.Filename, ContentType: firstReq.ContentType, Size: firstReq.Size, Sha256: firstReq.SHA256,
	})
	must(t, e)
	if openLimited.StatusCode() != 429 || openLimited.JSON429 == nil || openLimited.JSON429.Code != sdk.ProblemCodeMediaOpenUploadsLimit || openLimited.JSON429.Limit == nil || *openLimited.JSON429.Limit != 1 {
		t.Fatalf("unexpected open uploads limit response: %d %s", openLimited.StatusCode(), string(openLimited.Body))
	}

	// 3. Transfer slot busy -> 503 with Retry-After header and media_transfer_busy.
	blocker := &blockingReader{source: bytes.NewReader(firstData), entered: make(chan struct{}), release: make(chan struct{})}
	doneCh := make(chan error, 1)
	go func() {
		_, err := h.s.Upload(h.ctx, user, u1.JSON200.UploadId, "block-slot", blocker)
		doneCh <- err
	}()
	<-blocker.entered

	busyRes, e := client.UploadContentWithBodyWithResponse(h.ctx, u1.JSON200.UploadId, &sdk.UploadContentParams{IdempotencyKey: "busy-try"}, "application/octet-stream", bytes.NewReader(firstData))
	must(t, e)
	close(blocker.release)
	must(t, <-doneCh)
	if busyRes.StatusCode() != 503 || busyRes.JSON503 == nil || busyRes.JSON503.Code != sdk.ProblemCodeMediaTransferBusy || busyRes.HTTPResponse.Header.Get("Retry-After") == "" || busyRes.JSON503.RetryAfterSeconds == nil {
		t.Fatalf("unexpected transfer busy response: %d header=%q body=%s", busyRes.StatusCode(), busyRes.HTTPResponse.Header.Get("Retry-After"), string(busyRes.Body))
	}

	// Complete first file and test version limit, reference limit, archive too large, and file limit.
	u1Fresh := h.ready(t, h.newUpload(t, "u2-valid", firstData))
	fileID := u1Fresh.FileID
	verLimited, e := client.CreateUploadWithResponse(h.ctx, &sdk.CreateUploadParams{IdempotencyKey: "ver-limit"}, sdk.UploadRequest{
		FileId: &fileID, Purpose: firstReq.Purpose, Filename: firstReq.Filename, ContentType: firstReq.ContentType, Size: firstReq.Size, Sha256: firstReq.SHA256,
	})
	must(t, e)
	if verLimited.StatusCode() != 409 || verLimited.JSON409 == nil || verLimited.JSON409.Code != sdk.ProblemCodeMediaVersionLimitExceeded || verLimited.JSON409.Limit == nil || *verLimited.JSON409.Limit != 1 {
		t.Fatalf("unexpected version limit response: %d %s", verLimited.StatusCode(), string(verLimited.Body))
	}

	fileLimited, e := client.CreateUploadWithResponse(h.ctx, &sdk.CreateUploadParams{IdempotencyKey: "file-limit"}, sdk.UploadRequest{
		Purpose: firstReq.Purpose, Filename: firstReq.Filename, ContentType: firstReq.ContentType, Size: firstReq.Size, Sha256: firstReq.SHA256,
	})
	must(t, e)
	if fileLimited.StatusCode() != 409 || fileLimited.JSON409 == nil || fileLimited.JSON409.Code != sdk.ProblemCodeMediaFileLimitExceeded || fileLimited.JSON409.Limit == nil || *fileLimited.JSON409.Limit != 2 {
		t.Fatalf("unexpected file limit response: %d %s", fileLimited.StatusCode(), string(fileLimited.Body))
	}

	ref := h.bind(t, u1Fresh, "ref-1")
	refLimited, e := client.AttachReferenceWithResponse(h.ctx, u1Fresh.ID, &sdk.AttachReferenceParams{IdempotencyKey: "ref-limit"}, sdk.Binding{Module: "fixture", ResourceId: "ref-2"})
	must(t, e)
	if refLimited.StatusCode() != 409 || refLimited.JSON409 == nil || refLimited.JSON409.Code != sdk.ProblemCodeMediaReferenceLimitExceeded || refLimited.JSON409.Limit == nil || *refLimited.JSON409.Limit != 1 {
		t.Fatalf("unexpected reference limit response: %d %s", refLimited.StatusCode(), string(refLimited.Body))
	}

	archBig, e := client.ArchiveManifestWithResponse(h.ctx, sdk.ArchiveRequest{References: []string{ref.ID}})
	must(t, e)
	if archBig.StatusCode() != 413 || archBig.JSON413 == nil || archBig.JSON413.Code != sdk.ProblemCodeMediaArchiveTooLarge || archBig.JSON413.Limit == nil || *archBig.JSON413.Limit != 5 {
		t.Fatalf("unexpected archive too large response: %d %s", archBig.StatusCode(), string(archBig.Body))
	}
}
func mustJSON(t *testing.T, v any) []byte { t.Helper(); b, e := json.Marshal(v); must(t, e); return b }
func TestHTTPReuseReturnsDurableSession(t *testing.T) {
	h := newFixture(t)
	data := []byte("same lecture")
	h.newUpload(t, "source", data)
	must(t, h.s.Close(h.ctx))
	var e error
	h.s, e = media.New(h.repo, h.policy, &lostStore{Store: h.store, loseCreate: true}, h.cfg)
	must(t, e)
	handler, e := httpapi.New(h.s, authenticate{}, 1<<20)
	must(t, e)
	r := request(data)
	r.ReuseExisting = true
	post := func() media.Version {
		w := httptest.NewRecorder()
		q := httptest.NewRequest("POST", "/api/v1/media/uploads", bytes.NewReader(mustJSON(t, r)))
		q.Header.Set("Content-Type", "application/json")
		q.Header.Set("Idempotency-Key", "reuse")
		q.Header.Set("Authorization", "Bearer fixture-owner")
		handler.ServeHTTP(w, q)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		var v media.Version
		must(t, json.Unmarshal(w.Body.Bytes(), &v))
		return v
	}
	v := post()
	if !v.Reused || v.UploadID == "" || v.State != "verifying" {
		t.Fatal(v.State)
	}
	_, e = h.s.CancelUpload(h.ctx, user, v.UploadID, "cancel")
	must(t, e)
	again := post()
	if again.UploadID != v.UploadID || again.State != "cancelled" {
		t.Fatal(again.State)
	}
	var count int
	must(t, h.db.QueryRow("SELECT count(*) FROM media.versions").Scan(&count))
	if count != 2 {
		t.Fatal(count)
	}
}
func TestHTTPReviewAndBodyLimits(t *testing.T) {
	h := newFixture(t)
	handler, e := httpapi.New(h.s, authenticate{}, 32)
	must(t, e)
	call := func(method, path, key, typ string, b io.Reader) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, b)
		r.Header.Set("Authorization", "Bearer fixture-owner")
		r.Header.Set("Content-Type", typ)
		r.Header.Set("Idempotency-Key", key)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	data := []byte("lecture")
	v := h.newUpload(t, "review", data)
	url := "/api/v1/media/versions/" + v.ID + "/review-content"
	w := call("GET", url, "", "", nil)
	if w.Code != 200 || !bytes.Equal(w.Body.Bytes(), data) {
		t.Fatalf("review returned %d", w.Code)
	}
	h.policy.deny("media.versions.review", true)
	w = call("GET", url, "", "", nil)
	if w.Code != 403 || bytes.Contains(w.Body.Bytes(), data) {
		t.Fatal(w.Code)
	}
	q := request(data)
	q.Size = h.cfg.Profiles["documents"].MaxSize + 1
	w = call("POST", "/api/v1/media/uploads", "big", "application/json", bytes.NewReader(mustJSON(t, q)))
	if w.Code != 413 {
		t.Fatal(w.Code)
	}
	w = call("POST", "/api/v1/media/uploads", "json", "application/json", strings.NewReader(strings.Repeat(" ", 65537)+"{}"))
	if w.Code != 413 {
		t.Fatal(w.Code)
	}
	fresh, e := h.s.CreateUpload(h.ctx, user, "new", request(data))
	must(t, e)
	w = call("PUT", "/api/v1/media/uploads/"+fresh.UploadID+"/content", "long", "application/octet-stream", bytes.NewReader(append(bytes.Clone(data), 'x')))
	if w.Code != 413 {
		t.Fatal(w.Code)
	}
	longRequest := httptest.NewRequest("PUT", "/api/v1/media/uploads/"+fresh.UploadID+"/content", strings.NewReader(strings.Repeat("x", 64)))
	longRequest.ContentLength = -1
	longRequest.Header.Set("Content-Type", "application/octet-stream")
	longRequest.Header.Set("Authorization", "Bearer fixture-owner")
	longRequest.Header.Set("Idempotency-Key", "long")
	streamed := httptest.NewRecorder()
	handler.ServeHTTP(streamed, longRequest)
	if streamed.Code != 413 {
		t.Fatal("streamed oversize", streamed.Code)
	}
	st, e := h.s.GetVersion(h.ctx, user, fresh.ID)
	must(t, e)
	if st.Healthy != 0 || st.State == "rejected" {
		t.Fatal(st.State, st.Healthy)
	}
	r, e := http.NewRequest("POST", "/api/v1/media/versions/"+v.ID+"/approval", nil)
	must(t, e)
	r.Header.Set("Authorization", "Bearer fixture-owner")
	r.Header.Set("Idempotency-Key", "nil-body")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
}
func TestPortableFilenamesAndRouting(t *testing.T) {
	h := newFixture(t)
	q := request([]byte("lecture"))
	for _, name := range []string{"lecture:1.pdf", "CON.pdf", "lecture.", "slides ", "lPt2.txt"} {
		q.Filename = name
		if _, e := h.s.CreateUpload(h.ctx, user, "name", q); !errors.Is(e, media.ErrFilenameInvalid) || !errors.Is(e, media.ErrInput) {
			t.Fatal(name, e)
		}
	}
	var count int
	must(t, h.db.QueryRow("SELECT count(*) FROM media.files").Scan(&count))
	if count != 0 {
		t.Fatal(count)
	}
	handler, e := httpapi.New(h.s, authenticate{}, 100)
	must(t, e)
	for _, c := range []struct {
		m, path string
		code    int
	}{{"GET", "/missing", 404}, {"POST", "/api/v1/media/files", 405}} {
		r := httptest.NewRequest(c.m, c.path, nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != c.code || !json.Valid(w.Body.Bytes()) || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal(c, w.Code, w.Body.String())
		}
		if c.code == 405 && !strings.Contains(w.Header().Get("Allow"), "GET") {
			t.Fatal("missing Allow")
		}
	}
}

type deadlineRecorder struct {
	*httptest.ResponseRecorder
	read, write []time.Time
}

func (w *deadlineRecorder) SetReadDeadline(d time.Time) error { w.read = append(w.read, d); return nil }
func (w *deadlineRecorder) SetWriteDeadline(d time.Time) error {
	w.write = append(w.write, d)
	return nil
}
func TestConnectionDeadlineClearedAfterRequest(t *testing.T) {
	h := newFixture(t)
	handler, e := httpapi.New(h.s, authenticate{}, 100)
	must(t, e)
	r := httptest.NewRequest("GET", "/api/v1/media/files", nil)
	r.Header.Set("Authorization", "Bearer fixture-owner")
	w := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	handler.ServeHTTP(w, r)
	for _, values := range [][]time.Time{w.read, w.write} {
		if len(values) != 2 || values[0].IsZero() || !values[1].IsZero() {
			t.Fatal(values)
		}
	}
}
