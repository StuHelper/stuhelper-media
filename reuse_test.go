package media_test

import (
	"bytes"
	"context"
	"errors"
	media "github.com/StuHelper/stuhelper-media"
	"testing"
)

func totalWrites(h *fixture) int {
	h.provider.mu.Lock()
	defer h.provider.mu.Unlock()
	n := 0
	for _, c := range h.provider.writes {
		n += c
	}
	return n
}
func TestOwnContentReuseKeepsIndependentApprovalAndReferences(t *testing.T) {
	h := newFixture(t)
	data := []byte("repeat the same lecture file")
	source := h.newUpload(t, "source", data)
	before := totalWrites(h)
	r := request(data)
	r.ReuseExisting = true
	r.Filename = "renamed-lecture.txt"
	copy, e := h.s.CreateUpload(h.ctx, user, "reuse", r)
	must(t, e)
	if !copy.Reused || copy.State != "awaiting_approval" || copy.Approved || copy.FileID == source.FileID || copy.ID == source.ID || copy.Filename != r.Filename {
		t.Fatalf("independent reuse %+v", copy)
	}
	if totalWrites(h) != before {
		t.Fatal("same-protection reuse transmitted provider bytes")
	}
	again, e := h.s.CreateUpload(h.ctx, user, "reuse", r)
	must(t, e)
	if again.ID != copy.ID {
		t.Fatal("replay created another file")
	}
	// The source remains unapproved while the copied version can be approved.
	copiedReady := h.ready(t, copy)
	ref := h.bind(t, copiedReady, "copy-business")
	st, e := h.s.GetVersion(h.ctx, user, source.ID)
	must(t, e)
	if st.Approved || st.State != "awaiting_approval" {
		t.Fatal("approval leaked to source")
	}
	sourceFile, e := h.s.GetFile(h.ctx, user, source.FileID)
	must(t, e)
	_, e = h.s.DeleteFile(h.ctx, user, sourceFile.ID, "remove-source", sourceFile.Revision)
	must(t, e)
	h.cycle(t)
	var out bytes.Buffer
	must(t, h.s.Download(h.ctx, user, ref.ID, &out))
	if !bytes.Equal(out.Bytes(), data) {
		t.Fatal("source deletion removed copy")
	}
	copiedFile, e := h.s.GetFile(h.ctx, user, copy.FileID)
	must(t, e)
	if copiedFile.ID != copy.FileID {
		t.Fatal("file identity changed")
	}
}

type ownerPolicy struct{}

func (ownerPolicy) Authorize(_ context.Context, p media.Principal, action string, a media.Access) error {
	if action == "media.maintenance" && p == system {
		return nil
	}
	if p.Issuer != user.Issuer || a.Owner != p {
		return media.ErrDenied
	}
	return nil
}
func TestDigestAloneCannotReuseAnotherOwnersFile(t *testing.T) {
	h := newFixture(t)
	must(t, h.s.Close(h.ctx))
	var e error
	h.s, e = media.New(h.repo, ownerPolicy{}, h.store, h.cfg)
	must(t, e)
	data := []byte("private owner content")
	source := h.newUpload(t, "source", data)
	other := media.Principal{Issuer: user.Issuer, Subject: "another-user"}
	r := request(data)
	r.ReuseExisting = true
	copy, e := h.s.CreateUpload(h.ctx, other, "hash-only", r)
	must(t, e)
	if copy.Reused || copy.State != "created" {
		t.Fatal("hash proved another user's ownership")
	}
	if _, e = h.s.GetFile(h.ctx, other, source.FileID); !errors.Is(e, media.ErrDenied) {
		t.Fatal("foreign file metadata leaked", e)
	}
	before := totalWrites(h)
	copy, e = h.s.Upload(h.ctx, other, copy.UploadID, "actual-bytes", bytes.NewReader(data))
	must(t, e)
	if copy.State != "awaiting_approval" || totalWrites(h) != before {
		t.Fatal("verified duplicate wrote a second physical file")
	}
}
func TestReuseRequiresCurrentSourceRightsAndProfile(t *testing.T) {
	h := newFixture(t)
	data := []byte("source access may change")
	source := h.newUpload(t, "source", data)
	r := request(data)
	r.ReuseExisting = true
	h.policy.deny("media.files.read", true)
	fresh, e := h.s.CreateUpload(h.ctx, user, "read-revoked", r)
	must(t, e)
	if fresh.Reused {
		t.Fatal("reuse ignored current read permission")
	}
	h.policy.deny("media.files.read", false)
	// A changed purpose profile must not silently reuse the old approval context.
	originalProfile := h.cfg.Profiles["documents"]
	changedProfile := originalProfile
	changedProfile.MaxSize /= 2
	must(t, h.s.Close(h.ctx))
	h.cfg.Profiles["documents"] = changedProfile
	h.s, e = media.New(h.repo, h.policy, h.store, h.cfg)
	must(t, e)
	changed, e := h.s.CreateUpload(h.ctx, user, "profile-changed", r)
	must(t, e)
	if changed.Reused {
		t.Fatal("reuse ignored current purpose configuration")
	}
	must(t, h.s.Close(h.ctx))
	h.cfg.Profiles["documents"] = originalProfile
	h.s, e = media.New(h.repo, h.policy, h.store, h.cfg)
	must(t, e)
	file, e := h.s.GetFile(h.ctx, user, source.FileID)
	must(t, e)
	_, e = h.s.SetFileState(h.ctx, user, file.ID, "disable-source", file.Revision, true)
	must(t, e)
	fresh, e = h.s.CreateUpload(h.ctx, user, "disabled", r)
	must(t, e)
	if fresh.Reused {
		t.Fatal("reused disabled source")
	}
}
func TestReuseLostResponseAndRestartDoNotResendOrApprove(t *testing.T) {
	h := newFixture(t)
	data := []byte("already published content reused")
	source := h.ready(t, h.newUpload(t, "source", data))
	_ = h.bind(t, source, "source-business")
	must(t, h.s.Close(h.ctx))
	fault := &lostStore{Store: h.store, loseCreate: true}
	var e error
	h.s, e = media.New(h.repo, h.policy, fault, h.cfg)
	must(t, e)
	r := request(data)
	r.ReuseExisting = true
	if _, e = h.s.CreateUpload(h.ctx, user, "reuse-lost", r); !errors.Is(e, media.ErrUnavailable) {
		t.Fatal(e)
	}
	writes := totalWrites(h)
	must(t, h.s.Close(h.ctx))
	h.s, e = media.New(h.repo, h.policy, fault, h.cfg)
	must(t, e)
	h.cycle(t)
	v, e := h.s.CreateUpload(h.ctx, user, "reuse-lost", r)
	must(t, e)
	if !v.Reused || v.Approved || v.State != "awaiting_approval" || totalWrites(h) != writes {
		t.Fatalf("recovery duplicated or approved: %+v writes=%d/%d", v, totalWrites(h), writes)
	}
}

func TestCancelledReuseReleasesOnlyTheNewHandle(t *testing.T) {
	h := newFixture(t)
	data := []byte("cancel a pending duplicate")
	source := h.newUpload(t, "source", data)
	must(t, h.s.Close(h.ctx))
	fault := &lostStore{Store: h.store, loseCreate: true}
	var e error
	h.s, e = media.New(h.repo, h.policy, fault, h.cfg)
	must(t, e)
	r := request(data)
	r.ReuseExisting = true
	copy, e := h.s.CreateUpload(h.ctx, user, "pending-reuse", r)
	if !errors.Is(e, media.ErrUnavailable) {
		t.Fatal(e)
	}
	if copy.ID == "" || copy.UploadID == "" {
		t.Fatal("lost durable upload identity")
	}
	_, e = h.s.CancelUpload(h.ctx, user, copy.UploadID, "cancel")
	must(t, e)
	h.cycle(t)
	copyView, e := h.s.GetVersion(h.ctx, user, copy.ID)
	must(t, e)
	if !copyView.CleanupComplete || copyView.State != "cancelled" {
		t.Fatalf("copy cleanup %+v", copyView)
	}
	original, e := h.s.GetVersion(h.ctx, user, source.ID)
	must(t, e)
	if original.CleanupComplete || original.State != "awaiting_approval" || original.Healthy < 1 {
		t.Fatal("cancelled source content")
	}
}
