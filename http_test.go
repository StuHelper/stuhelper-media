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
	response, e := client.DownloadReference(h.ctx, ref.ID, nil)
	must(t, e)
	body, e := io.ReadAll(response.Body)
	response.Body.Close()
	must(t, e)
	if response.StatusCode != 200 || !bytes.Equal(body, data) {
		t.Fatal(response.StatusCode, string(body))
	}
	_, params, e := mime.ParseMediaType(response.Header.Get("Content-Disposition"))
	must(t, e)
	if params["filename"] != r.Filename || response.Header.Get("Cache-Control") != "private, no-cache" || response.Header.Get("ETag") != `"`+r.SHA256+`"` || response.Header.Get("Accept-Ranges") != "bytes" {
		t.Fatal("unsafe download headers", response.Header)
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
	denied, e = client.DownloadReference(h.ctx, ref.ID, nil)
	must(t, e)
	defer denied.Body.Close()
	b, e := io.ReadAll(denied.Body)
	must(t, e)
	if denied.StatusCode != 403 || bytes.Contains(b, data) || denied.Header.Get("Content-Disposition") != "" || denied.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("denial leaked content", denied.StatusCode)
	}
}

func TestHTTPDownloadConditionalRangeInlineAndCustomArchiveFilename(t *testing.T) {
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

	pdfBytes := []byte("%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n")
	pdfReq := request(pdfBytes)
	pdfReq.Filename = "微积分讲义.pdf"
	pdfReq.ContentType = "application/pdf"
	createdPDF, e := h.s.CreateUpload(h.ctx, user, "pdf-dl", pdfReq)
	must(t, e)
	uploadedPDF, e := h.s.Upload(h.ctx, user, createdPDF.UploadID, "pdf-bytes", bytes.NewReader(pdfBytes))
	must(t, e)
	pdfRef := h.bind(t, h.ready(t, uploadedPDF), "pdf-ref")
	etag := `"` + pdfReq.SHA256 + `"`

	// 1. HEAD request returns metadata without body bytes.
	inline := sdk.HeadReferenceParamsDispositionInline
	headRes, e := client.HeadReference(h.ctx, pdfRef.ID, &sdk.HeadReferenceParams{Disposition: &inline})
	must(t, e)
	headBody, e := io.ReadAll(headRes.Body)
	headRes.Body.Close()
	must(t, e)
	dispKind, dispParams, e := mime.ParseMediaType(headRes.Header.Get("Content-Disposition"))
	must(t, e)
	if headRes.StatusCode != 200 || len(headBody) != 0 || headRes.Header.Get("ETag") != etag || dispKind != "inline" || dispParams["filename"] != pdfReq.Filename || headRes.Header.Get("Content-Security-Policy") != "default-src 'none'; sandbox" {
		t.Fatalf("unexpected HEAD response: %d headers=%v", headRes.StatusCode, headRes.Header)
	}

	// 2. Conditional GET with matching ETag returns 304; after permission revocation returns 403.
	notMod, e := client.DownloadReference(h.ctx, pdfRef.ID, &sdk.DownloadReferenceParams{IfNoneMatch: &etag})
	must(t, e)
	notMod.Body.Close()
	if notMod.StatusCode != 304 || notMod.Header.Get("ETag") != etag {
		t.Fatalf("expected 304 Not Modified, got %d", notMod.StatusCode)
	}
	h.policy.deny("media.references.download", true)
	revokedCond, e := client.DownloadReference(h.ctx, pdfRef.ID, &sdk.DownloadReferenceParams{IfNoneMatch: &etag})
	must(t, e)
	revokedCond.Body.Close()
	if revokedCond.StatusCode != 403 || revokedCond.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("revoked conditional request must return 403, got %d", revokedCond.StatusCode)
	}
	h.policy.deny("media.references.download", false)

	// 3. Range requests: slice, suffix, If-Range mismatch fallback, and 416 unsatisfiable.
	rSlice := "bytes=0-7"
	partRes, e := client.DownloadReference(h.ctx, pdfRef.ID, &sdk.DownloadReferenceParams{Range: &rSlice})
	must(t, e)
	partBody, e := io.ReadAll(partRes.Body)
	partRes.Body.Close()
	must(t, e)
	if partRes.StatusCode != 206 || !bytes.Equal(partBody, pdfBytes[:8]) || partRes.Header.Get("Content-Range") != "bytes 0-7/45" {
		t.Fatalf("unexpected Range 0-7 response: %d %q %s", partRes.StatusCode, partBody, partRes.Header.Get("Content-Range"))
	}

	rSuffix := "bytes=-7"
	sufRes, e := client.DownloadReference(h.ctx, pdfRef.ID, &sdk.DownloadReferenceParams{Range: &rSuffix})
	must(t, e)
	sufBody, e := io.ReadAll(sufRes.Body)
	sufRes.Body.Close()
	must(t, e)
	if sufRes.StatusCode != 206 || !bytes.Equal(sufBody, pdfBytes[len(pdfBytes)-7:]) {
		t.Fatalf("unexpected suffix Range response: %d %q", sufRes.StatusCode, sufBody)
	}

	staleIfRange := `"0000000000000000000000000000000000000000000000000000000000000000"`
	fullFallback, e := client.DownloadReference(h.ctx, pdfRef.ID, &sdk.DownloadReferenceParams{Range: &rSlice, IfRange: &staleIfRange})
	must(t, e)
	fbBody, e := io.ReadAll(fullFallback.Body)
	fullFallback.Body.Close()
	must(t, e)
	if fullFallback.StatusCode != 200 || !bytes.Equal(fbBody, pdfBytes) {
		t.Fatalf("expected 200 full body when If-Range mismatches, got %d", fullFallback.StatusCode)
	}

	badRange := "bytes=999-1000"
	unsatRes, e := client.DownloadReference(h.ctx, pdfRef.ID, &sdk.DownloadReferenceParams{Range: &badRange})
	must(t, e)
	unsatRes.Body.Close()
	if unsatRes.StatusCode != 416 || unsatRes.Header.Get("Content-Range") != "bytes */45" {
		t.Fatalf("expected 416 Range Not Satisfiable, got %d %s", unsatRes.StatusCode, unsatRes.Header.Get("Content-Range"))
	}

	// 4. Non-whitelisted MIME type (text/plain) forces attachment even when disposition=inline is requested.
	txtVersion := h.ready(t, h.newUpload(t, "txt-dl", []byte("plain text note")))
	txtRef := h.bind(t, txtVersion, "txt-ref")
	dlInline := sdk.DownloadReferenceParamsDispositionInline
	txtRes, e := client.DownloadReference(h.ctx, txtRef.ID, &sdk.DownloadReferenceParams{Disposition: &dlInline})
	must(t, e)
	txtRes.Body.Close()
	txtKind, _, e := mime.ParseMediaType(txtRes.Header.Get("Content-Disposition"))
	must(t, e)
	if txtKind != "attachment" {
		t.Fatalf("non-whitelisted MIME type served as %s instead of attachment", txtKind)
	}

	// 5. Custom archive filename sanitization and EstimatedZipBytes accuracy.
	customName := "C/C++ 程序设计: 历年卷"
	manifestRes, e := client.ArchiveManifestWithResponse(h.ctx, sdk.ArchiveRequest{References: []string{pdfRef.ID, txtRef.ID}, Filename: &customName})
	must(t, e)
	if manifestRes.StatusCode() != 200 || manifestRes.JSON200 == nil || manifestRes.JSON200.EstimatedZipBytes <= manifestRes.JSON200.TotalSize {
		t.Fatalf("unexpected ArchiveManifest response: %d %s", manifestRes.StatusCode(), string(manifestRes.Body))
	}
	zipRes, e := client.DownloadArchive(h.ctx, sdk.ArchiveRequest{References: []string{pdfRef.ID, txtRef.ID}, Filename: &customName})
	must(t, e)
	zipBytes, e := io.ReadAll(zipRes.Body)
	zipRes.Body.Close()
	must(t, e)
	zipKind, zipParams, e := mime.ParseMediaType(zipRes.Header.Get("Content-Disposition"))
	must(t, e)
	if zipRes.StatusCode != 200 || zipKind != "attachment" || zipParams["filename"] != "C_C++ 程序设计_ 历年卷.zip" {
		t.Fatalf("unexpected archive Content-Disposition: %s", zipRes.Header.Get("Content-Disposition"))
	}
	if int64(len(zipBytes)) != manifestRes.JSON200.EstimatedZipBytes {
		t.Fatalf("estimated_zip_bytes=%d actual=%d", manifestRes.JSON200.EstimatedZipBytes, len(zipBytes))
	}

	dotsOnly := "..."
	badZip, e := client.ArchiveManifestWithResponse(h.ctx, sdk.ArchiveRequest{References: []string{pdfRef.ID}, Filename: &dotsOnly})
	must(t, e)
	if badZip.StatusCode() != 400 {
		t.Fatalf("expected 400 for invalid dots-only archive filename, got %d", badZip.StatusCode())
	}
}
func mustJSON(t *testing.T, v any) []byte { t.Helper(); b, e := json.Marshal(v); must(t, e); return b }
