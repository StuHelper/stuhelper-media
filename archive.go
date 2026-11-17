package media

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ArchiveLimits returns the configured limits so a composing business service
// can reject an incompatible package policy before accepting user requests.
func (s *Service) ArchiveLimits() (files int, bytes int64) {
	return s.cfg.MaxArchiveFiles, s.cfg.MaxArchiveBytes
}

func (s *Service) ListFiles(ctx context.Context, p Principal, limit int, cursor string) (FilePage, error) {
	out := FilePage{Items: []File{}}
	if limit < 1 || limit > 100 || (cursor != "" && !idOK(cursor)) {
		return out, ErrInput
	}
	if !p.Valid() {
		return out, ErrDenied
	}
	ctx, cancel := context.WithTimeout(ctx, s.cfg.OperationTimeout)
	defer cancel()
	err := s.repo.Transaction(ctx, func(tx Transaction) error {
		rows, e := tx.Files(p, limit, cursor)
		if e != nil {
			return e
		}
		for _, f := range rows {
			if f.Owner != p {
				return ErrUnavailable
			}
			// Authorization receives the persisted owner and purpose, just as file detail does.
			e = s.authorize(ctx, p, "media.files.read", Access{FileID: f.ID, Purpose: f.Purpose, Owner: f.Owner, Protection: f.Protection})
			if errors.Is(e, ErrDenied) {
				continue
			}
			if e != nil {
				return e
			}
			out.Items = append(out.Items, f.File)
		}
		if len(rows) == limit {
			out.NextCursor = rows[len(rows)-1].ID
		}
		return nil
	})
	return out, err
}

func (s *Service) ArchiveManifest(ctx context.Context, p Principal, ids []string) (ArchiveManifest, error) {
	out := ArchiveManifest{Entries: []ArchiveEntry{}}
	if len(ids) < 1 || len(ids) > s.cfg.MaxArchiveFiles {
		return out, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, s.cfg.OperationTimeout)
	defer cancel()
	seen := map[string]bool{}
	for n, id := range ids {
		if !idOK(id) || seen[id] {
			return ArchiveManifest{}, ErrInput
		}
		seen[id] = true
		v, e := s.ReferenceVersion(ctx, p, id)
		if e != nil {
			return ArchiveManifest{}, e
		}
		if v.Size > s.cfg.MaxArchiveBytes-out.TotalSize {
			return ArchiveManifest{}, ErrCapacity
		}
		out.TotalSize += v.Size
		out.Entries = append(out.Entries, ArchiveEntry{ReferenceID: id, VersionID: v.ID, Path: fmt.Sprintf("files/%03d/%s", n+1, v.Filename), Filename: v.Filename, Size: v.Size, SHA256: v.SHA256})
	}
	out.EstimatedZipBytes = estimateArchiveZipBytes(out)
	out.EstimatedZipBytes = estimateArchiveZipBytes(out)
	return out, nil
}

type countingDiscard int64

func (c *countingDiscard) Write(p []byte) (int, error) {
	*c += countingDiscard(len(p))
	return len(p), nil
}

func estimateArchiveZipBytes(m ArchiveManifest) int64 {
	var overhead countingDiscard
	z := zip.NewWriter(&overhead)
	for _, entry := range m.Entries {
		_, _ = z.CreateHeader(&zip.FileHeader{Name: entry.Path, Method: zip.Store})
	}
	if w, err := z.CreateHeader(&zip.FileHeader{Name: "manifest.json", Method: zip.Store}); err == nil {
		_ = json.NewEncoder(w).Encode(m)
	}
	_ = z.Close()
	return int64(overhead) + m.TotalSize
}

func SanitizeArchiveFilename(raw string) (string, error) {
	if raw == "" {
		return "files.zip", nil
	}
	if !utf8.ValidString(raw) || len(raw) > 240 {
		return "", ErrInput
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", ErrInput
	}
	if len(trimmed) >= 4 && strings.EqualFold(trimmed[len(trimmed)-4:], ".zip") {
		trimmed = trimmed[:len(trimmed)-4]
	}
	var b strings.Builder
	for _, r := range trimmed {
		if r < 32 || unicode.IsControl(r) || strings.ContainsRune(`<>:"/\|?*`, r) {
			b.WriteByte('_')
			continue
		}
		b.WriteRune(r)
	}
	cleaned := strings.Trim(b.String(), " .")
	if cleaned == "" {
		return "", ErrInput
	}
	stem := cleaned
	if dot := strings.IndexByte(stem, '.'); dot >= 0 {
		stem = stem[:dot]
	}
	switch strings.ToUpper(stem) {
	case "CON", "PRN", "AUX", "NUL",
		"COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
		"LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9":
		cleaned = "_" + cleaned
	}
	for len(cleaned) > 200 {
		_, size := utf8.DecodeLastRuneInString(cleaned)
		cleaned = cleaned[:len(cleaned)-size]
	}
	cleaned = strings.Trim(cleaned, " .")
	if cleaned == "" {
		return "", ErrInput
	}
	return cleaned + ".zip", nil
}

// Archive streams verified entries without retaining archive bytes. A single
// transfer slot covers the entire package, including all entry downloads.
func (s *Service) Archive(ctx context.Context, p Principal, ids []string, dst io.Writer) error {
	if dst == nil {
		return ErrInput
	}
	ctx, done, e := s.begin(ctx)
	if e != nil {
		return e
	}
	defer done()
	manifest, e := s.ArchiveManifest(ctx, p, ids)
	if e != nil {
		return e
	}
	z := zip.NewWriter(&contextWriter{ctx: ctx, dst: dst})
	for _, entry := range manifest.Entries {
		// Delay headers until Download has validated bytes and current authority.
		lazy := &archiveEntryWriter{archive: z, name: entry.Path}
		if e = s.download(ctx, p, entry.ReferenceID, lazy); e != nil {
			return e
		}
	}
	// Revocation during the package transfer prevents a valid complete archive.
	if _, e = s.ArchiveManifest(ctx, p, ids); e != nil {
		return e
	}
	w, e := z.CreateHeader(&zip.FileHeader{Name: "manifest.json", Method: zip.Store})
	if e != nil {
		return e
	}
	if e = json.NewEncoder(w).Encode(manifest); e != nil {
		return e
	}
	return z.Close()
}

type archiveEntryWriter struct {
	archive *zip.Writer
	name    string
	writer  io.Writer
}

func (w *archiveEntryWriter) Write(b []byte) (int, error) {
	if w.writer == nil {
		var e error
		w.writer, e = w.archive.CreateHeader(&zip.FileHeader{Name: w.name, Method: zip.Store})
		if e != nil {
			return 0, e
		}
	}
	return w.writer.Write(b)
}

type contextWriter struct {
	ctx context.Context
	dst io.Writer
}

func (w *contextWriter) Write(b []byte) (int, error) {
	if e := w.ctx.Err(); e != nil {
		return 0, e
	}
	return w.dst.Write(b)
}
