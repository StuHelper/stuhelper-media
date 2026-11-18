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
	"time"
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
func mustJSON(t *testing.T, v any) []byte { t.Helper(); b, e := json.Marshal(v); must(t, e); return b }
func TestPortableFilenamesAndRouting(t *testing.T) {
	h := newFixture(t)
	q := request([]byte("lecture"))
	for _, name := range []string{"lecture:1.pdf", "CON.pdf", "lecture.", "slides ", "lPt2.txt"} {
		q.Filename = name
		if _, e := h.s.CreateUpload(h.ctx, user, "name", q); e != media.ErrInput {
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
