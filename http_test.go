package media_test

import (
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

func TestHTTPResumableUploadAndProfileCatalog(t *testing.T) {
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

	profilesRes, e := client.ListProfilesWithResponse(h.ctx)
	must(t, e)
	if profilesRes.StatusCode() != 200 || profilesRes.JSON200 == nil || len(profilesRes.JSON200.Profiles) != 1 || profilesRes.JSON200.Profiles[0].Purpose != "documents" {
		t.Fatalf("unexpected ListProfiles HTTP response: %d %s", profilesRes.StatusCode(), string(profilesRes.Body))
	}
	for _, secret := range []string{"quarantine", "published", "account-", "credential"} {
		if bytes.Contains(profilesRes.Body, []byte(secret)) {
			t.Fatal("profile catalog exposed internal classification", secret)
		}
	}

	data := []byte("resumable upload over generated HTTP SDK")
	r := request(data)
	created, e := client.CreateUploadWithResponse(h.ctx, &sdk.CreateUploadParams{IdempotencyKey: "http-chunk-create"}, sdk.UploadRequest{Purpose: r.Purpose, Filename: r.Filename, ContentType: r.ContentType, Size: r.Size, Sha256: r.SHA256})
	must(t, e)
	if created.StatusCode() != 200 || created.JSON200 == nil || created.JSON200.UploadedBytes != 0 {
		t.Fatalf("unexpected create response: %d %s", created.StatusCode(), string(created.Body))
	}

	part1, e := client.AppendUploadContentWithBodyWithResponse(h.ctx, created.JSON200.UploadId, &sdk.AppendUploadContentParams{IdempotencyKey: "http-c1", UploadOffset: 0}, "application/octet-stream", bytes.NewReader(data[:16]))
	must(t, e)
	if part1.StatusCode() != 200 || part1.JSON200 == nil || part1.JSON200.UploadedBytes != 16 || part1.JSON200.State != "uploading" {
		t.Fatalf("unexpected part1 response: %d %s", part1.StatusCode(), string(part1.Body))
	}

	conflict, e := client.AppendUploadContentWithBodyWithResponse(h.ctx, created.JSON200.UploadId, &sdk.AppendUploadContentParams{IdempotencyKey: "http-c2-bad", UploadOffset: 0}, "application/octet-stream", bytes.NewReader(data[:16]))
	must(t, e)
	if conflict.StatusCode() != 409 {
		t.Fatal("expected 409 on stale offset", conflict.StatusCode())
	}

	status, e := client.GetUploadWithResponse(h.ctx, created.JSON200.UploadId)
	must(t, e)
	if status.StatusCode() != 200 || status.JSON200 == nil || status.JSON200.UploadedBytes != 16 {
		t.Fatalf("unexpected GetUpload progress: %d %s", status.StatusCode(), string(status.Body))
	}

	part2, e := client.AppendUploadContentWithBodyWithResponse(h.ctx, created.JSON200.UploadId, &sdk.AppendUploadContentParams{IdempotencyKey: "http-c2", UploadOffset: 16}, "application/octet-stream", bytes.NewReader(data[16:]))
	must(t, e)
	if part2.StatusCode() != 200 || part2.JSON200 == nil || part2.JSON200.UploadedBytes != int64(len(data)) || part2.JSON200.State != "awaiting_approval" {
		t.Fatalf("unexpected final chunk response: %d %s", part2.StatusCode(), string(part2.Body))
	}
}
func mustJSON(t *testing.T, v any) []byte { t.Helper(); b, e := json.Marshal(v); must(t, e); return b }
