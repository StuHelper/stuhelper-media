package media

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const maxStagingFiles = 10000

type uploadStaging struct {
	mu            sync.Mutex
	root          *os.Root
	ephemeralPath string
	limit         int64
	reserved      int64
	sizes         map[string]int64
	busy          map[string]bool
}

func partName(versionID string) string {
	return "upload-" + versionID + ".part"
}

func parsePartVersionID(name string) (string, bool) {
	if !strings.HasPrefix(name, "upload-") || !strings.HasSuffix(name, ".part") {
		return "", false
	}
	id := strings.TrimSuffix(strings.TrimPrefix(name, "upload-"), ".part")
	return id, idOK(id)
}

func openUploadStaging(parent string, limit int64) (*uploadStaging, error) {
	if limit < 1 {
		return nil, ErrInput
	}
	s := &uploadStaging{
		limit: limit,
		sizes: map[string]int64{},
		busy:  map[string]bool{},
	}
	if parent == "" {
		tmp, err := os.MkdirTemp("", "stuhelper-media-staging-*")
		if err != nil {
			return nil, ErrUnavailable
		}
		root, err := os.OpenRoot(tmp)
		if err != nil {
			_ = os.RemoveAll(tmp)
			return nil, ErrUnavailable
		}
		s.root = root
		s.ephemeralPath = tmp
		return s, nil
	}
	if !filepath.IsAbs(parent) {
		return nil, ErrInput
	}
	base, err := os.OpenRoot(parent)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer base.Close()
	if err = base.Mkdir("media-staging-v1", 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, ErrUnavailable
	}
	info, err := base.Lstat("media-staging-v1")
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, ErrInput
	}
	root, err := base.OpenRoot("media-staging-v1")
	if err != nil {
		return nil, ErrUnavailable
	}
	s.root = root
	ok := false
	defer func() {
		if !ok {
			_ = s.close()
		}
	}()
	dir, err := root.Open(".")
	if err != nil {
		return nil, ErrUnavailable
	}
	defer dir.Close()
	entries, err := dir.ReadDir(maxStagingFiles + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, ErrUnavailable
	}
	if len(entries) > maxStagingFiles {
		return nil, ErrCapacity
	}
	for _, entry := range entries {
		id, valid := parsePartVersionID(entry.Name())
		if !valid {
			return nil, ErrConflict
		}
		fi, err := entry.Info()
		if err != nil || !fi.Mode().IsRegular() {
			return nil, ErrConflict
		}
		sz := fi.Size()
		if sz > s.limit-s.reserved {
			return nil, ErrCapacity
		}
		s.sizes[id] = sz
		s.reserved += sz
	}
	ok = true
	return s, nil
}

func (s *uploadStaging) size(versionID string) int64 {
	if s == nil || !idOK(versionID) {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.root == nil {
		return 0
	}
	fi, err := s.root.Stat(partName(versionID))
	if err != nil {
		return 0
	}
	return fi.Size()

}

func (s *uploadStaging) appendChunk(ctx context.Context, versionID string, offset, maxTotal int64, src io.Reader) (int64, int64, string, []byte, error) {
	if s == nil || !idOK(versionID) || offset < 0 || offset >= maxTotal || src == nil {
		return offset, 0, "", nil, ErrInput
	}
	name := partName(versionID)
	s.mu.Lock()
	if s.root == nil {
		s.mu.Unlock()
		return offset, 0, "", nil, ErrUnavailable
	}
	if s.busy[versionID] {
		s.mu.Unlock()
		return offset, 0, "", nil, ErrConflict
	}
	var cur int64
	info, statErr := s.root.Stat(name)
	switch {
	case statErr == nil:
		cur = info.Size()
	case errors.Is(statErr, os.ErrNotExist):
		if len(s.sizes) >= maxStagingFiles {
			s.mu.Unlock()
			return offset, 0, "", nil, ErrCapacity
		}
	default:
		s.mu.Unlock()
		return offset, 0, "", nil, ErrUnavailable
	}
	if cur < offset || ctx.Err() != nil {
		s.mu.Unlock()
		return cur, 0, "", nil, ErrConflict
	}
	f, err := s.root.OpenFile(name, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		s.mu.Unlock()
		return offset, 0, "", nil, ErrUnavailable
	}
	// The caller verified offset against the committed DB row under its lease.
	// A larger file contains bytes from an interrupted or uncommitted append.
	if cur > offset {
		if err = f.Truncate(offset); err != nil {
			_ = f.Close()
			s.mu.Unlock()
			return offset, 0, "", nil, ErrUnavailable
		}
	}
	s.reserved += offset - s.sizes[versionID]
	s.sizes[versionID] = offset
	s.busy[versionID] = true
	s.mu.Unlock()

	var written int64
	rollback := func() {
		_ = f.Truncate(offset)
		_ = f.Close()
		s.mu.Lock()
		defer s.mu.Unlock()
		delete(s.busy, versionID)
		s.reserved -= written
		if offset == 0 && s.root != nil {
			_ = s.root.Remove(name)
			delete(s.sizes, versionID)
		} else {
			s.sizes[versionID] = offset
		}
	}

	if _, err = f.Seek(offset, io.SeekStart); err != nil {
		rollback()
		return offset, 0, "", nil, ErrUnavailable
	}

	limit := maxTotal - offset
	limited := io.LimitReader(src, limit+1)
	hasher := sha256.New()
	buf := make([]byte, 32*1024)
	for {
		if err = ctx.Err(); err != nil {
			rollback()
			return offset, 0, "", nil, ErrUnavailable
		}
		n, readErr := limited.Read(buf)
		if n > 0 {
			delta := int64(n)
			if written+delta > limit {
				rollback()
				return offset, 0, "", nil, ErrIntegrity
			}
			s.mu.Lock()
			if delta > s.limit-s.reserved {
				s.mu.Unlock()
				rollback()
				return offset, 0, "", nil, ErrCapacity
			}
			s.reserved += delta
			written += delta
			s.sizes[versionID] = offset + written
			s.mu.Unlock()

			if _, wErr := f.Write(buf[:n]); wErr != nil {
				rollback()
				return offset, 0, "", nil, ErrUnavailable
			}
			_, _ = hasher.Write(buf[:n])
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			rollback()
			var maxBytes *http.MaxBytesError
			if errors.As(readErr, &maxBytes) {
				return offset, 0, "", nil, readErr
			}
			return offset, 0, "", nil, ErrUnavailable
		}
	}

	if written == 0 {
		rollback()
		return offset, 0, "", nil, ErrInput
	}

	prefixLen := min(int64(3072), offset+written)
	prefix := make([]byte, prefixLen)
	if _, err = f.ReadAt(prefix, 0); err != nil && !errors.Is(err, io.EOF) {
		rollback()
		return offset, 0, "", nil, ErrUnavailable
	}
	if s.ephemeralPath == "" {
		if err = f.Sync(); err != nil {
			rollback()
			return offset, 0, "", nil, ErrUnavailable
		}
	}
	if err = f.Close(); err != nil {
		s.mu.Lock()
		delete(s.busy, versionID)
		s.mu.Unlock()
		return offset, 0, "", nil, ErrUnavailable
	}
	s.mu.Lock()
	delete(s.busy, versionID)
	s.mu.Unlock()
	return offset + written, written, hex.EncodeToString(hasher.Sum(nil)), prefix, nil
}

func (s *uploadStaging) openVerified(ctx context.Context, versionID string, expectedSize int64, expectedSHA256 string) (*os.File, error) {
	if s == nil || !idOK(versionID) {
		return nil, ErrInput
	}
	s.mu.Lock()
	if s.root == nil {
		s.mu.Unlock()
		return nil, ErrUnavailable
	}
	f, err := s.root.Open(partName(versionID))
	s.mu.Unlock()
	if err != nil {
		return nil, ErrUnavailable
	}
	hasher := sha256.New()
	buf := make([]byte, 32*1024)
	var total int64
	for {
		if err = ctx.Err(); err != nil {
			_ = f.Close()
			return nil, ErrUnavailable
		}
		n, rErr := f.Read(buf)
		if n > 0 {
			total += int64(n)
			if total > expectedSize {
				_ = f.Close()
				return nil, ErrIntegrity
			}
			_, _ = hasher.Write(buf[:n])
		}
		if errors.Is(rErr, io.EOF) {
			break
		}
		if rErr != nil {
			_ = f.Close()
			return nil, ErrUnavailable
		}
	}
	if total != expectedSize || hex.EncodeToString(hasher.Sum(nil)) != expectedSHA256 {
		_ = f.Close()
		return nil, ErrIntegrity
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		_ = f.Close()
		return nil, ErrUnavailable
	}
	return f, nil
}

func (s *uploadStaging) remove(versionID string) {
	if s == nil || !idOK(versionID) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.root == nil || s.busy[versionID] {
		return
	}
	err := s.root.Remove(partName(versionID))
	if err == nil || errors.Is(err, os.ErrNotExist) {
		s.reserved -= s.sizes[versionID]
		delete(s.sizes, versionID)
	}
}

func (s *uploadStaging) close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	root := s.root
	s.root = nil
	ephemeral := s.ephemeralPath
	s.ephemeralPath = ""
	s.mu.Unlock()
	var err error
	if root != nil {
		err = root.Close()
	}
	if ephemeral != "" {
		_ = os.RemoveAll(ephemeral)
	}
	return err
}
