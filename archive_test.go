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
	"testing"
	"time"
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

type hiddenFilePolicy struct {
	base   media.Authorizer
	hidden map[string]bool
}

func (p hiddenFilePolicy) Authorize(ctx context.Context, actor media.Principal, action string, a media.Access) error {
	if action == "media.files.read" && p.hidden[a.FileID] {
		return media.ErrDenied
	}
	return p.base.Authorize(ctx, actor, action, a)
}

func TestFileListOwnerCursorAndCurrentPermission(t *testing.T) {
	h := newFixture(t)
	createdVersions := make([]media.Version, 0, 3)
	for _, key := range []string{"list-a", "list-b", "list-c"} {
		h.clock.Add(time.Second)
		createdVersions = append(createdVersions, h.newUpload(t, key, []byte(key)))
	}
	// Add a second version on the newest file and approve the oldest file to test summary & state filter.
	v2Req := request([]byte("list-c-v2"))
	v2Req.FileID = createdVersions[2].FileID
	v2Req.Filename = "第二版讲义.txt"
	v2, e := h.s.CreateUpload(h.ctx, user, "list-c-v2", v2Req)
	must(t, e)
	_ = h.ready(t, createdVersions[0])

	first, e := h.s.ListFiles(h.ctx, user, 2, "")
	must(t, e)
	if len(first.Items) != 2 || first.NextCursor == "" {
		t.Fatal("pagination", first)
	}
	if first.Items[0].ID != createdVersions[2].FileID || first.Items[1].ID != createdVersions[1].FileID {
		t.Fatalf("expected newest-first order, got %s then %s", first.Items[0].ID, first.Items[1].ID)
	}
	if first.Items[0].VersionCount != 2 || first.Items[0].LatestVersion == nil || first.Items[0].LatestVersion.ID != v2.ID || first.Items[0].LatestVersion.Number != 2 || first.Items[0].LatestVersion.Filename != "第二版讲义.txt" || first.Items[0].LatestVersion.State != "created" {
		t.Fatalf("unexpected latest_version summary: %+v %+v", first.Items[0], first.Items[0].LatestVersion)
	}
	second, e := h.s.ListFiles(h.ctx, user, 2, first.NextCursor)
	must(t, e)
	if len(second.Items) != 1 || second.NextCursor != "" || second.Items[0].ID != createdVersions[0].FileID || second.Items[0].LatestVersion == nil || second.Items[0].LatestVersion.State != "ready" || !second.Items[0].LatestVersion.Approved {
		t.Fatalf("cursor or ready state summary mismatch: %+v", second)
	}

	readyOnly, e := h.s.ListFilesFiltered(h.ctx, user, media.FileListFilter{Limit: 10, Purpose: "documents", State: "ready"})
	must(t, e)
	if len(readyOnly.Items) != 1 || readyOnly.Items[0].ID != createdVersions[0].FileID {
		t.Fatalf("state filter mismatch: %+v", readyOnly)
	}
	otherPurpose, e := h.s.ListFilesFiltered(h.ctx, user, media.FileListFilter{Limit: 10, Purpose: "nonexistent"})
	must(t, e)
	if len(otherPurpose.Items) != 0 {
		t.Fatalf("expected empty list for unmatched purpose: %+v", otherPurpose)
	}
	if _, e = h.s.ListFilesFiltered(h.ctx, user, media.FileListFilter{Limit: 10, State: "invalid_state"}); !errors.Is(e, media.ErrInput) {
		t.Fatal("accepted invalid state filter", e)
	}

	// Partial permission denial auto-refills up to limit within bounded 5*limit scan.
	filteredSvc, e := media.New(h.repo, hiddenFilePolicy{
		base:   h.policy,
		hidden: map[string]bool{createdVersions[2].FileID: true, createdVersions[1].FileID: true},
	}, h.store, h.cfg)
	must(t, e)
	defer filteredSvc.Close(h.ctx)
	refilled, e := filteredSvc.ListFiles(h.ctx, user, 1, "")
	must(t, e)
	if len(refilled.Items) != 1 || refilled.Items[0].ID != createdVersions[0].FileID {
		t.Fatalf("expected bounded scan to skip 2 hidden files and return permitted file: %+v", refilled)
	}

	outsider := media.Principal{Issuer: user.Issuer, Subject: "someone-else"}
	page, e := h.s.ListFiles(h.ctx, user, 100, "")
	must(t, e)
	if len(page.Items) != 3 {
		t.Fatal("expected 3 owner items", len(page.Items))
	}
	page, e = h.s.ListFiles(h.ctx, outsider, 100, "")
	must(t, e)
	if len(page.Items) != 0 {
		t.Fatal("cross-owner list")
	}

	// Create 3 more files (total 6 > 5*limit when limit=1) to verify cursor advances past hidden rows.
	for _, key := range []string{"list-d", "list-e", "list-f"} {
		h.clock.Add(time.Second)
		h.newUpload(t, key, []byte(key))
	}
	h.policy.deny("media.files.read", true)
	page, e = h.s.ListFiles(h.ctx, user, 1, "")
	must(t, e)
	if len(page.Items) != 0 || page.NextCursor == "" {
		t.Fatal("denial leaked or stopped cursor", page)
	}
	tail, e := h.s.ListFiles(h.ctx, user, 1, page.NextCursor)
	must(t, e)
	if len(tail.Items) != 0 || tail.NextCursor != "" {
		t.Fatal("cursor after hidden rows did not finish cleanly", tail)
	}
	h.policy.deny("media.files.read", false)

	if _, e = h.s.ListFiles(h.ctx, user, 101, ""); !errors.Is(e, media.ErrInput) {
		t.Fatal(e)
	}
	if _, e = h.s.ListFiles(h.ctx, user, 10, "malformed-cursor"); !errors.Is(e, media.ErrInput) {
		t.Fatal("accepted malformed composite cursor", e)
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
