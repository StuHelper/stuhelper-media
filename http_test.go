package media_test

import (
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
	"strings"
	"testing"
)

type authenticate struct{}

func (authenticate) Authenticate(r *http.Request) (media.Principal, error) {
	if r.Header.Get("Authorization") == "Bearer fixture-owner" {
		return user, nil
	}
	return media.Principal{}, media.ErrDenied
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

type blockingReader struct {
	entered chan struct{}
	release chan struct{}
}

func (r *blockingReader) Read(_ []byte) (int, error) {
	select {
	case <-r.entered:
	default:
		close(r.entered)
	}
	<-r.release
	return 0, io.EOF
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
	blocker := &blockingReader{entered: make(chan struct{}), release: make(chan struct{})}
	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)
		_, _ = h.s.Upload(h.ctx, user, u1.JSON200.UploadId, "block-slot", blocker)
	}()
	<-blocker.entered

	busyRes, e := client.UploadContentWithBodyWithResponse(h.ctx, u1.JSON200.UploadId, &sdk.UploadContentParams{IdempotencyKey: "busy-try"}, "application/octet-stream", bytes.NewReader(firstData))
	must(t, e)
	close(blocker.release)
	<-doneCh
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
