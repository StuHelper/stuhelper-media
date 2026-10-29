package media

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	return out, nil
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
