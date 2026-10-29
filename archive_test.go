package media_test

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	media "github.com/StuHelper/stuhelper-media"
	"io"
	"strings"
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
