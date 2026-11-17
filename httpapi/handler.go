// Package httpapi exposes authenticated file operations without provider details.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	media "github.com/StuHelper/stuhelper-media"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type Authenticator interface {
	Authenticate(*http.Request) (media.Principal, error)
}
type handler struct {
	s    *media.Service
	auth Authenticator
	max  int64
}
type endpoint func(http.ResponseWriter, *http.Request, media.Principal) (any, error)

func New(s *media.Service, a Authenticator, max int64) (http.Handler, error) {
	if s == nil || a == nil || max < 1 || max > 1<<30 {
		return nil, media.ErrInput
	}
	h := &handler{s, a, max}
	m := http.NewServeMux()
	h.mount(m, "POST /api/v1/media/uploads", false, func(_ http.ResponseWriter, r *http.Request, p media.Principal) (any, error) {
		var q media.UploadRequest
		if e := decode(r, &q); e != nil {
			return nil, e
		}
		return s.CreateUpload(r.Context(), p, r.Header.Get("Idempotency-Key"), q)
	})
	h.mount(m, "GET /api/v1/media/uploads/{id}", false, func(_ http.ResponseWriter, r *http.Request, p media.Principal) (any, error) {
		return s.GetUpload(r.Context(), p, r.PathValue("id"))
	})
	h.mount(m, "DELETE /api/v1/media/uploads/{id}", false, func(_ http.ResponseWriter, r *http.Request, p media.Principal) (any, error) {
		if e := empty(r); e != nil {
			return nil, e
		}
		return s.CancelUpload(r.Context(), p, r.PathValue("id"), r.Header.Get("Idempotency-Key"))
	})
	h.mount(m, "PUT /api/v1/media/uploads/{id}/content", true, func(_ http.ResponseWriter, r *http.Request, p media.Principal) (any, error) {
		typ, _, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if e != nil || typ != "application/octet-stream" {
			return nil, media.ErrInput
		}
		return s.Upload(r.Context(), p, r.PathValue("id"), r.Header.Get("Idempotency-Key"), r.Body)
	})
	h.mount(m, "GET /api/v1/media/files", false, func(_ http.ResponseWriter, r *http.Request, p media.Principal) (any, error) {
		limit := 50
		if raw := r.URL.Query().Get("limit"); raw != "" {
			var e error
			limit, e = strconv.Atoi(raw)
			if e != nil {
				return nil, media.ErrInput
			}
		}
		for name, values := range r.URL.Query() {
			if len(values) != 1 || (name != "limit" && name != "cursor") {
				return nil, media.ErrInput
			}
		}
		return s.ListFiles(r.Context(), p, limit, r.URL.Query().Get("cursor"))
	})
	h.mount(m, "POST /api/v1/media/archives/manifest", false, func(_ http.ResponseWriter, r *http.Request, p media.Principal) (any, error) {
		var q media.ArchiveRequest
		if e := decode(r, &q); e != nil {
			return nil, e
		}
		if _, e := media.SanitizeArchiveFilename(q.Filename); e != nil {
			return nil, e
		}
		return s.ArchiveManifest(r.Context(), p, q.References)
	})
	h.mount(m, "POST /api/v1/media/archives/content", false, func(w http.ResponseWriter, r *http.Request, p media.Principal) (any, error) {
		var q media.ArchiveRequest
		if e := decode(r, &q); e != nil {
			return nil, e
		}
		archiveName, e := media.SanitizeArchiveFilename(q.Filename)
		if e != nil {
			return nil, e
		}
		dst := &archiveWriter{ResponseWriter: w, filename: archiveName}
		e = s.Archive(r.Context(), p, q.References, dst)
		if e != nil && dst.started {
			panic(http.ErrAbortHandler)
		}
		return nil, e
	})
	h.mount(m, "GET /api/v1/media/files/{id}", false, func(_ http.ResponseWriter, r *http.Request, p media.Principal) (any, error) {
		return s.GetFile(r.Context(), p, r.PathValue("id"))
	})
	h.mount(m, "DELETE /api/v1/media/files/{id}", false, func(_ http.ResponseWriter, r *http.Request, p media.Principal) (any, error) {
		var q struct {
			Revision int64 `json:"revision"`
		}
		if e := decode(r, &q); e != nil {
			return nil, e
		}
		return s.DeleteFile(r.Context(), p, r.PathValue("id"), r.Header.Get("Idempotency-Key"), q.Revision)
	})
	h.mount(m, "PUT /api/v1/media/files/{id}/state", false, func(_ http.ResponseWriter, r *http.Request, p media.Principal) (any, error) {
		var q struct {
			Revision int64 `json:"revision"`
			Disabled bool  `json:"disabled"`
		}
		if e := decode(r, &q); e != nil {
			return nil, e
		}
		return s.SetFileState(r.Context(), p, r.PathValue("id"), r.Header.Get("Idempotency-Key"), q.Revision, q.Disabled)
	})
	h.mount(m, "GET /api/v1/media/versions/{id}", false, func(_ http.ResponseWriter, r *http.Request, p media.Principal) (any, error) {
		return s.GetVersion(r.Context(), p, r.PathValue("id"))
	})
	h.mount(m, "POST /api/v1/media/versions/{id}/approval", false, func(_ http.ResponseWriter, r *http.Request, p media.Principal) (any, error) {
		if e := empty(r); e != nil {
			return nil, e
		}
		return s.Approve(r.Context(), p, r.PathValue("id"), r.Header.Get("Idempotency-Key"))
	})
	h.mount(m, "POST /api/v1/media/versions/{id}/references", false, func(_ http.ResponseWriter, r *http.Request, p media.Principal) (any, error) {
		var q media.Binding
		if e := decode(r, &q); e != nil {
			return nil, e
		}
		return s.Attach(r.Context(), p, r.PathValue("id"), r.Header.Get("Idempotency-Key"), q)
	})
	h.mount(m, "GET /api/v1/media/references/{id}", false, func(_ http.ResponseWriter, r *http.Request, p media.Principal) (any, error) {
		return s.GetReference(r.Context(), p, r.PathValue("id"))
	})
	h.mount(m, "DELETE /api/v1/media/references/{id}", false, func(_ http.ResponseWriter, r *http.Request, p media.Principal) (any, error) {
		if e := empty(r); e != nil {
			return nil, e
		}
		return s.Release(r.Context(), p, r.PathValue("id"), r.Header.Get("Idempotency-Key"))
	})
	h.mount(m, "POST /api/v1/media/references/{id}/publication", false, func(_ http.ResponseWriter, r *http.Request, p media.Principal) (any, error) {
		if e := empty(r); e != nil {
			return nil, e
		}
		return s.Publish(r.Context(), p, r.PathValue("id"), r.Header.Get("Idempotency-Key"))
	})
	h.mount(m, "HEAD /api/v1/media/references/{id}/content", false, h.headReference)
	h.mount(m, "GET /api/v1/media/references/{id}/content", false, h.download)
	return m, nil
}
func (h *handler) mount(m *http.ServeMux, path string, upload bool, run endpoint) {
	m.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		if r.Body == nil {
			r.Body = http.NoBody
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		p, e := h.auth.Authenticate(r)
		if e != nil || !p.Valid() {
			if errors.Is(e, media.ErrUnavailable) {
				problem(w, 503, media.ErrUnavailable.Error())
			} else {
				problem(w, 401, "authentication_required")
			}
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
		defer cancel()
		r = r.WithContext(ctx)
		controller := http.NewResponseController(w)
		deadline, _ := ctx.Deadline()
		_ = controller.SetReadDeadline(deadline)
		_ = controller.SetWriteDeadline(deadline)
		stop := context.AfterFunc(ctx, func() { _ = controller.SetReadDeadline(time.Now()); _ = controller.SetWriteDeadline(time.Now()) })
		defer stop()
		max := int64(65536)
		if upload {
			max = h.max + 1
		}
		r.Body = http.MaxBytesReader(w, r.Body, max)
		if len(r.Header.Values("Idempotency-Key")) > 1 {
			problem(w, 400, media.ErrInput.Error())
			return
		}
		out, e := run(w, r, p)
		if e != nil {
			failure(w, e)
			return
		}
		if out != nil {
			writeJSON(w, 200, out)
		}
	})
}
func decode(r *http.Request, out any) error {
	typ, _, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if e != nil || typ != "application/json" {
		return media.ErrInput
	}
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if e = d.Decode(out); e != nil {
		return media.ErrInput
	}
	if d.Decode(new(any)) != io.EOF {
		return media.ErrInput
	}
	return nil
}
func empty(r *http.Request) error {
	b, e := io.ReadAll(io.LimitReader(r.Body, 1))
	if e != nil || len(b) > 0 {
		return media.ErrInput
	}
	return nil
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Del("Content-Length")
	w.Header().Del("Content-Disposition")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func problem(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"code": code})
}
func failure(w http.ResponseWriter, e error) {
	status, code := 503, media.ErrUnavailable.Error()
	for _, entry := range []struct {
		e      error
		status int
	}{{media.ErrInput, 400}, {media.ErrDenied, 403}, {media.ErrNotFound, 404}, {media.ErrConflict, 409}, {media.ErrExpired, 410}, {media.ErrIntegrity, 422}, {media.ErrType, 422}, {media.ErrCapacity, 503}} {
		if errors.Is(e, entry.e) {
			status = entry.status
			code = entry.e.Error()
			break
		}
	}
	var limit *http.MaxBytesError
	if errors.As(e, &limit) {
		status = 413
		code = "media_upload_too_large"
	}
	problem(w, status, code)
}

func safeInlineContentType(contentType string) bool {
	switch contentType {
	case "application/pdf", "image/png", "image/jpeg", "image/webp":
		return true
	default:
		return false
	}
}

func parseDispositionQuery(r *http.Request) (string, error) {
	disposition := "attachment"
	for name, values := range r.URL.Query() {
		if len(values) != 1 || name != "disposition" {
			return "", media.ErrInput
		}
		switch values[0] {
		case "attachment", "inline":
			disposition = values[0]
		default:
			return "", media.ErrInput
		}
	}
	return disposition, nil
}

func applyContentHeaders(w http.ResponseWriter, v media.Version, requestedDisposition string) {
	disposition := "attachment"
	if requestedDisposition == "inline" && safeInlineContentType(v.ContentType) {
		disposition = "inline"
		w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
	}
	w.Header().Set("Content-Type", v.ContentType)
	w.Header().Set("Content-Disposition", mime.FormatMediaType(disposition, map[string]string{"filename": v.Filename}))
	w.Header().Set("ETag", `"`+v.SHA256+`"`)
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Cache-Control", "private, no-cache")
}

func ifNoneMatch(raw, etag string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false
	}
	if raw == "*" {
		return true
	}
	for _, part := range strings.Split(raw, ",") {
		candidate := strings.TrimSpace(part)
		if strings.HasPrefix(candidate, "W/") {
			candidate = strings.TrimSpace(strings.TrimPrefix(candidate, "W/"))
		}
		if candidate == etag {
			return true
		}
	}
	return false
}

func parseByteRange(raw, ifRange, etag string, total int64) (partial bool, start, end int64, unsatisfiable bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || total <= 0 {
		return false, 0, 0, false
	}
	ifRange = strings.TrimSpace(ifRange)
	if ifRange != "" && ifRange != etag {
		return false, 0, 0, false
	}
	if !strings.HasPrefix(raw, "bytes=") {
		return false, 0, 0, false
	}
	spec := strings.TrimSpace(strings.TrimPrefix(raw, "bytes="))
	if strings.Contains(spec, ",") {
		return false, 0, 0, false
	}
	parts := strings.Split(spec, "-")
	if len(parts) != 2 || (parts[0] == "" && parts[1] == "") {
		return false, 0, 0, true
	}
	if parts[0] == "" {
		suffix, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil || suffix <= 0 {
			return false, 0, 0, true
		}
		if suffix >= total {
			return true, 0, total - 1, false
		}
		return true, total - suffix, total - 1, false
	}
	s, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || s < 0 || s >= total {
		return false, 0, 0, true
	}
	if parts[1] == "" {
		return true, s, total - 1, false
	}
	e, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || e < s {
		return false, 0, 0, true
	}
	if e >= total {
		e = total - 1
	}
	return true, s, e, false
}

type downloadWriter struct {
	http.ResponseWriter
	version     media.Version
	disposition string
	partial     bool
	rangeStart  int64
	rangeEnd    int64
	offset      int64
	started     bool
}

func (w *downloadWriter) Write(b []byte) (int, error) {
	if !w.started {
		applyContentHeaders(w.ResponseWriter, w.version, w.disposition)
		if w.partial {
			w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", w.rangeStart, w.rangeEnd, w.version.Size))
			w.Header().Set("Content-Length", strconv.FormatInt(w.rangeEnd-w.rangeStart+1, 10))
			w.WriteHeader(http.StatusPartialContent)
		} else {
			w.Header().Set("Content-Length", strconv.FormatInt(w.version.Size, 10))
			w.WriteHeader(http.StatusOK)
		}
		w.started = true
	}
	if !w.partial {
		return w.ResponseWriter.Write(b)
	}
	chunkStart := w.offset
	chunkEnd := w.offset + int64(len(b))
	w.offset = chunkEnd
	sliceStart := max(chunkStart, w.rangeStart)
	sliceEnd := min(chunkEnd, w.rangeEnd+1)
	if sliceStart >= sliceEnd {
		return len(b), nil
	}
	if _, err := w.ResponseWriter.Write(b[sliceStart-chunkStart : sliceEnd-chunkStart]); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (h *handler) headReference(w http.ResponseWriter, r *http.Request, p media.Principal) (any, error) {
	disposition, e := parseDispositionQuery(r)
	if e != nil {
		return nil, e
	}
	v, e := h.s.InspectReferenceDownload(r.Context(), p, r.PathValue("id"))
	if e != nil {
		return nil, e
	}
	etag := `"` + v.SHA256 + `"`
	if ifNoneMatch(r.Header.Get("If-None-Match"), etag) {
		w.Header().Set("ETag", etag)
		w.Header().Set("Accept-Ranges", "bytes")
		w.Header().Set("Cache-Control", "private, no-cache")
		w.WriteHeader(http.StatusNotModified)
		return nil, nil
	}
	applyContentHeaders(w, v, disposition)
	w.Header().Set("Content-Length", strconv.FormatInt(v.Size, 10))
	w.WriteHeader(http.StatusOK)
	return nil, nil
}

func (h *handler) download(w http.ResponseWriter, r *http.Request, p media.Principal) (any, error) {
	disposition, e := parseDispositionQuery(r)
	if e != nil {
		return nil, e
	}
	v, e := h.s.InspectReferenceDownload(r.Context(), p, r.PathValue("id"))
	if e != nil {
		return nil, e
	}
	etag := `"` + v.SHA256 + `"`
	if ifNoneMatch(r.Header.Get("If-None-Match"), etag) {
		w.Header().Set("ETag", etag)
		w.Header().Set("Accept-Ranges", "bytes")
		w.Header().Set("Cache-Control", "private, no-cache")
		w.WriteHeader(http.StatusNotModified)
		return nil, nil
	}
	partial, start, end, unsatisfiable := parseByteRange(r.Header.Get("Range"), r.Header.Get("If-Range"), etag, v.Size)
	if unsatisfiable {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", v.Size))
		problem(w, http.StatusRequestedRangeNotSatisfiable, media.ErrInput.Error())
		return nil, nil
	}
	dst := &downloadWriter{
		ResponseWriter: w,
		version:        v,
		disposition:    disposition,
		partial:        partial,
		rangeStart:     start,
		rangeEnd:       end,
	}
	e = h.s.Download(r.Context(), p, r.PathValue("id"), dst)
	if e != nil && dst.started {
		panic(http.ErrAbortHandler)
	}
	return nil, e
}

type archiveWriter struct {
	http.ResponseWriter
	filename string
	started  bool
}

func (w *archiveWriter) Write(b []byte) (int, error) {
	if !w.started {
		name := w.filename
		if name == "" {
			name = "files.zip"
		}
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name}))
		w.WriteHeader(200)
		w.started = true
	}
	return w.ResponseWriter.Write(b)
}
