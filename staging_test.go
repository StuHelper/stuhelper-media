package media

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
)

func TestStagingReservationAndFileLimit(t *testing.T) {
	s, err := openUploadStaging("", 4)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.close(); err != nil {
			t.Error(err)
		}
	})
	f, err := s.root.OpenFile(partName("active"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	// The writer has reserved four bytes and has not yet issued the physical write.
	s.sizes["active"] = 4
	s.busy["active"] = true
	s.reserved = 4
	if got := s.size("active"); got != 0 {
		t.Fatal(got)
	}
	_, _, _, _, err = s.appendChunk(context.Background(), "second", 0, 1, bytes.NewReader([]byte("b")))
	if !errors.Is(err, ErrCapacity) || s.reserved != 4 {
		t.Fatal("reservation changed", s.reserved, err)
	}
	delete(s.busy, "active")
	s.remove("active")

	for i := 0; i < maxStagingFiles; i++ {
		s.sizes[fmt.Sprintf("existing-%d", i)] = 0
	}
	_, _, _, _, err = s.appendChunk(context.Background(), "extra", 0, 1, bytes.NewReader([]byte("b")))
	if !errors.Is(err, ErrCapacity) {
		t.Fatal("file limit", err)
	}
	if _, err = s.root.Stat(partName("extra")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unexpected part file", err)
	}
}
