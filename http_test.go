package media_test

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
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

func TestHTTPGeneratedSDKRejectsUntrustedFieldsAndProtectsContent(t *testing.T) {
	h := newFixture(t)
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

func mustJSON(t *testing.T, v any) []byte { t.Helper(); b, e := json.Marshal(v); must(t, e); return b }
