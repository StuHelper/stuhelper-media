package media_test

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	media "github.com/StuHelper/stuhelper-media"
	"io"
	"strings"
	"sync"
	"testing"
)

func TestArchiveManifestCurrentRightsAndSingleTransferSlot(t *testing.T) {
	h := newFixture(t)
	cfg := h.cfg
	cfg.ParallelTransfers = 1
	cfg.MaxArchiveFiles = 2
	cfg.MaxArchiveBytes = 100
	one, e := media.New(h.repo, h.policy, h.store, cfg)
	must(t, e)
	defer one.Close(h.ctx)
	a := h.ready(t, h.newUpload(t, "archive-a", []byte("first archive content")))
	b := h.ready(t, h.newUpload(t, "archive-b", []byte("second archive content")))
	ar := h.bind(t, a, "archive-a")
	br := h.bind(t, b, "archive-b")
	ids := []string{ar.ID, br.ID}
	manifest, e := one.ArchiveManifest(h.ctx, user, ids)
	must(t, e)
	if len(manifest.Entries) != 2 || manifest.Entries[0].Path == manifest.Entries[1].Path || manifest.TotalSize != a.Size+b.Size {
		t.Fatal("bad manifest", manifest)
	}
	var body bytes.Buffer
	must(t, one.Archive(h.ctx, user, ids, &body))
	z, e := zip.NewReader(bytes.NewReader(body.Bytes()), int64(body.Len()))
	must(t, e)
	if len(z.File) != 3 {
		t.Fatal("missing entries", len(z.File))
	}
	for n, want := range [][]byte{[]byte("first archive content"), []byte("second archive content")} {
		r, e := z.File[n].Open()
		must(t, e)
		got, e := io.ReadAll(r)
		r.Close()
		must(t, e)
		if !bytes.Equal(got, want) || z.File[n].Name != manifest.Entries[n].Path {
			t.Fatal("changed bytes or unsafe path")
		}
	}
	reader, e := z.File[2].Open()
	must(t, e)
	var saved media.ArchiveManifest
	must(t, json.NewDecoder(reader).Decode(&saved))
	reader.Close()
	if saved.Entries[0].SHA256 != a.SHA256 || saved.Entries[1].Filename != b.Filename {
		t.Fatal("manifest lost content identity")
	}
	if _, e = one.ArchiveManifest(h.ctx, user, []string{ar.ID, ar.ID}); !errors.Is(e, media.ErrInput) {
		t.Fatal("duplicate accepted", e)
	}
	tiny := cfg
	tiny.MaxArchiveBytes = 1
	bounded, e := media.New(h.repo, h.policy, h.store, tiny)
	must(t, e)
	defer bounded.Close(h.ctx)
	body.Reset()
	if e = bounded.Archive(h.ctx, user, ids, &body); !errors.Is(e, media.ErrCapacity) || body.Len() != 0 {
		t.Fatal("oversized archive emitted", e, body.Len())
	}
	h.provider.mu.Lock()
	h.provider.hook = func() { h.policy.deny("media.references.download", true) }
	h.provider.mu.Unlock()
	body.Reset()
	if e = one.Archive(h.ctx, user, ids, &body); !errors.Is(e, media.ErrDenied) || body.Len() != 0 {
		t.Fatal("revoked bytes or header emitted", e, body.Len())
	}
	h.policy.deny("media.references.download", false)
	_, e = h.s.Release(h.ctx, user, ar.ID, "archive-release")
	must(t, e)
	body.Reset()
	if e = one.Archive(h.ctx, user, ids, &body); !errors.Is(e, media.ErrDenied) || body.Len() != 0 {
		t.Fatal("released reference archived", e)
	}
}

func TestFileListOwnerCursorAndCurrentPermission(t *testing.T) {
	h := newFixture(t)
	for _, key := range []string{"list-a", "list-b", "list-c"} {
		h.newUpload(t, key, []byte(key))
	}
	first, e := h.s.ListFiles(h.ctx, user, 2, "")
	must(t, e)
	if len(first.Items) != 2 || first.NextCursor == "" {
		t.Fatal("pagination", first)
	}
	second, e := h.s.ListFiles(h.ctx, user, 2, first.NextCursor)
	must(t, e)
	if len(second.Items) != 1 || second.NextCursor != "" || second.Items[0].ID == first.Items[0].ID {
		t.Fatal("cursor repeats rows", second)
	}
	outsider := media.Principal{Issuer: user.Issuer, Subject: "someone-else"}
	page, e := h.s.ListFiles(h.ctx, outsider, 100, "")
	must(t, e)
	if len(page.Items) != 0 {
		t.Fatal("cross-owner list")
	}
	h.policy.deny("media.files.read", true)
	page, e = h.s.ListFiles(h.ctx, user, 2, "")
	must(t, e)
	if len(page.Items) != 0 || page.NextCursor == "" {
		t.Fatal("denial leaked or stopped cursor")
	}
	if _, e = h.s.ListFiles(h.ctx, user, 101, ""); !errors.Is(e, media.ErrInput) {
		t.Fatal(e)
	}
	b, e := json.Marshal(first)
	must(t, e)
	for _, secret := range []string{"owner", "protection", "account-", "credential"} {
		if strings.Contains(string(b), secret) {
			t.Fatal("private metadata", string(b))
		}
	}
}

func TestQuarantinedReviewDownloadRequiresSeparateCurrentPermission(t *testing.T) {
	h := newFixture(t)
	body := []byte("review before publication")
	v := h.newUpload(t, "review", body)
	var out bytes.Buffer
	must(t, h.s.ReviewDownload(h.ctx, user, v.ID, &out))
	if !bytes.Equal(out.Bytes(), body) {
		t.Fatal("wrong review content")
	}
	current, e := h.s.GetVersion(h.ctx, user, v.ID)
	must(t, e)
	if current.Approved || current.State != "awaiting_approval" {
		t.Fatal("review published content", current)
	}
	h.policy.deny("media.versions.review", true)
	out.Reset()
	if e = h.s.ReviewDownload(h.ctx, user, v.ID, &out); !errors.Is(e, media.ErrDenied) || out.Len() != 0 {
		t.Fatal("revoked reviewer received data", e)
	}
}

type protectionPolicy struct {
	mu                sync.Mutex
	denyQuarantineOps bool
}

func (p *protectionPolicy) Authorize(_ context.Context, actor media.Principal, action string, a media.Access) error {
	p.mu.Lock()
	denyQuarantine := p.denyQuarantineOps
	p.mu.Unlock()
	if actor == system && action == "media.maintenance" {
		return nil
	}
	reviewer := media.Principal{Issuer: user.Issuer, Subject: "quarantine-reviewer"}
	publicReviewer := media.Principal{Issuer: user.Issuer, Subject: "public-only-reviewer"}
	viewer := media.Principal{Issuer: user.Issuer, Subject: "public-viewer"}
	if actor == reviewer {
		if action == "media.versions.review" && a.Protection.Class == "quarantine" && !a.Protection.Public {
			return nil
		}
		return media.ErrDenied
	}
	if actor == publicReviewer {
		if action == "media.versions.review" && a.Protection.Public {
			return nil
		}
		return media.ErrDenied
	}
	if actor == viewer {
		if action == "media.files.read" && a.Protection.Public {
			return nil
		}
		return media.ErrDenied
	}
	if actor == user && a.Owner == user {
		if denyQuarantine && !a.Protection.Public {
			return media.ErrDenied
		}
		return nil
	}
	return media.ErrDenied
}

func TestUnapprovedQuarantineAndMultiVersionProtectionAuthorization(t *testing.T) {
	h := newFixture(t)
	must(t, h.s.Close(h.ctx))
	auth := &protectionPolicy{}
	s, e := media.New(h.repo, auth, h.store, h.cfg)
	must(t, e)
	h.s = s

	data := []byte("quarantined draft lecture notes")
	v1 := h.newUpload(t, "a01-v1", data)
	if v1.Approved || v1.State != "awaiting_approval" {
		t.Fatalf("unexpected initial state: %+v", v1)
	}

	viewer := media.Principal{Issuer: user.Issuer, Subject: "public-viewer"}
	if result, err := h.s.GetVersion(h.ctx, viewer, v1.ID); !errors.Is(err, media.ErrDenied) || result.ID != "" || result.UploadID != "" {
		t.Fatal("denied version lookup must return an empty result")
	}
	if result, err := h.s.GetUpload(h.ctx, viewer, v1.UploadID); !errors.Is(err, media.ErrDenied) || result.ID != "" || result.UploadID != "" {
		t.Fatal("denied upload lookup must return an empty result")
	}
	if _, e = h.s.GetFile(h.ctx, viewer, v1.FileID); !errors.Is(e, media.ErrDenied) {
		t.Fatalf("unapproved file metadata leaked via GetFile: %v", e)
	}

	reviewer := media.Principal{Issuer: user.Issuer, Subject: "quarantine-reviewer"}
	publicReviewer := media.Principal{Issuer: user.Issuer, Subject: "public-only-reviewer"}
	var buf bytes.Buffer
	if e = h.s.ReviewDownload(h.ctx, publicReviewer, v1.ID, &buf); !errors.Is(e, media.ErrDenied) || buf.Len() != 0 {
		t.Fatalf("public-only reviewer read quarantined bytes: err=%v len=%d", e, buf.Len())
	}
	must(t, h.s.ReviewDownload(h.ctx, reviewer, v1.ID, &buf))
	if !bytes.Equal(buf.Bytes(), data) {
		t.Fatal("quarantine reviewer received wrong bytes")
	}

	// Approve v1 before storage promotes it out of quarantine: physical bytes are still in quarantine,
	// so a public-only reviewer without quarantine clearance must still be denied.
	_, e = h.s.Approve(h.ctx, user, v1.ID, "a01-approve-v1")
	must(t, e)
	buf.Reset()
	if e = h.s.ReviewDownload(h.ctx, publicReviewer, v1.ID, &buf); !errors.Is(e, media.ErrDenied) || buf.Len() != 0 {
		t.Fatalf("public-only reviewer bypassed quarantine storage protection before promotion: err=%v len=%d", e, buf.Len())
	}

	// Promote v1 to ready (Published, Public=true). Now viewer can read the single-version public file.
	for n := 0; n < 8; n++ {
		h.cycle(t)
	}
	fv, e := h.s.GetFile(h.ctx, viewer, v1.FileID)
	must(t, e)
	if len(fv.Versions) != 1 {
		t.Fatalf("expected 1 version, got %d", len(fv.Versions))
	}

	// Add unapproved v2 (in Quarantine, Public=false) to the same logical file.
	next := request([]byte("unapproved second version"))
	next.FileID = v1.FileID
	v2, e := h.s.CreateUpload(h.ctx, user, "a01-v2-create", next)
	must(t, e)
	v2, e = h.s.Upload(h.ctx, user, v2.UploadID, "a01-v2-bytes", bytes.NewReader([]byte("unapproved second version")))
	must(t, e)

	// Viewer with only public read rights must not see v2 via GetFile.
	if _, e = h.s.GetFile(h.ctx, viewer, v1.FileID); !errors.Is(e, media.ErrDenied) {
		t.Fatalf("GetFile only checked v1 protection and leaked unapproved v2: %v", e)
	}

	// When owner loses quarantine-class permission, ListFiles, SetFileState and DeleteFile must check v2's protection too.
	ownerFile, e := h.s.GetFile(h.ctx, user, v1.FileID)
	must(t, e)
	auth.mu.Lock()
	auth.denyQuarantineOps = true
	auth.mu.Unlock()
	page, e := h.s.ListFiles(h.ctx, user, 10, "")
	must(t, e)
	if len(page.Items) != 0 {
		t.Fatalf("ListFiles ignored v2 quarantine protection and returned file: %+v", page.Items)
	}
	if _, e = h.s.SetFileState(h.ctx, user, ownerFile.ID, "a01-disable", ownerFile.Revision, true); !errors.Is(e, media.ErrDenied) {
		t.Fatalf("SetFileState ignored v2 quarantine protection: %v", e)
	}
	if _, e = h.s.DeleteFile(h.ctx, user, ownerFile.ID, "a01-delete", ownerFile.Revision); !errors.Is(e, media.ErrDenied) {
		t.Fatalf("DeleteFile ignored v2 quarantine protection: %v", e)
	}
}
func TestArchivePreservesLegacyNameInManifest(t *testing.T) {
	h := newFixture(t)
	v := h.ready(t, h.newUpload(t, "legacy", []byte("notes")))
	r := h.bind(t, v, "legacy")
	_, e := h.admin.Exec(`UPDATE media.versions SET data=jsonb_set(data,'{filename}',to_jsonb($1::text)) WHERE id=$2`, "notes.", v.ID)
	must(t, e)
	m, e := h.s.ArchiveManifest(h.ctx, user, []string{r.ID})
	must(t, e)
	if len(m.Entries) != 1 || m.Entries[0].Filename != "notes." || m.Entries[0].Path != "files/001/document" {
		t.Fatal(m.Entries)
	}
	var out bytes.Buffer
	must(t, h.s.Archive(h.ctx, user, []string{r.ID}, &out))
	z, e := zip.NewReader(bytes.NewReader(out.Bytes()), int64(out.Len()))
	must(t, e)
	if z.File[0].Name != m.Entries[0].Path {
		t.Fatal(z.File[0].Name)
	}
}
