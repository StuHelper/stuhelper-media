// Package httpapi exposes authenticated file operations without provider details.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	media "github.com/StuHelper/stuhelper-media"
	"io"
	"mime"
	"net/http"
	"strconv"
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
		return s.ArchiveManifest(r.Context(), p, q.References)
	})
	h.mount(m, "POST /api/v1/media/archives/content", false, func(w http.ResponseWriter, r *http.Request, p media.Principal) (any, error) {
		var q media.ArchiveRequest
		if e := decode(r, &q); e != nil {
			return nil, e
		}
		dst := &archiveWriter{ResponseWriter: w}
		e := s.Archive(r.Context(), p, q.References, dst)
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
	h.mount(m, "GET /api/v1/media/references/{id}/content", false, h.download)
	h.mount(m, "GET /api/v1/media/versions/{id}/review-content", false, func(w http.ResponseWriter, r *http.Request, p media.Principal) (any, error) {
		// Headers are committed only when the service writes verified bytes.
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", "attachment")
		dst := &reviewWriter{ResponseWriter: w}
		err := s.ReviewDownload(r.Context(), p, r.PathValue("id"), dst)
		if err != nil && dst.started {
			panic(http.ErrAbortHandler)
		}
		return nil, err
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler, pattern := m.Handler(r)
		if pattern == "" {
			handler.ServeHTTP(routeErrorWriter{w}, r)
			return
		}
		m.ServeHTTP(w, r)
	}), nil
}

// Preserve ServeMux method negotiation (including Allow) and format its errors
// with the same response contract as registered endpoints.
type routeErrorWriter struct{ http.ResponseWriter }

func (w routeErrorWriter) WriteHeader(status int) {
	code := "media_not_found"
	if status == http.StatusMethodNotAllowed {
		code = "method_not_allowed"
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	problem(w.ResponseWriter, status, code)
}
func (w routeErrorWriter) Write(b []byte) (int, error) { return len(b), nil }
func (h *handler) mount(m *http.ServeMux, path string, upload bool, run endpoint) {
	m.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		ctx, cancel := context.WithTimeout(r.Context(), h.s.OperationTimeout())
		defer cancel()
		r = r.WithContext(ctx)
		controller := http.NewResponseController(w)
		deadline, _ := ctx.Deadline()
		_ = controller.SetReadDeadline(deadline)
		_ = controller.SetWriteDeadline(deadline)
		expired := make(chan struct{})
		stop := context.AfterFunc(ctx, func() {
			defer close(expired)
			_ = controller.SetReadDeadline(time.Now())
			_ = controller.SetWriteDeadline(time.Now())
		})
		defer func() {
			if !stop() {
				<-expired
			}
			_ = controller.SetReadDeadline(time.Time{})
			_ = controller.SetWriteDeadline(time.Time{})
		}()
		p, e := h.auth.Authenticate(r)
		if e != nil || !p.Valid() {
			if errors.Is(e, media.ErrUnavailable) {
				problem(w, 503, media.ErrUnavailable.Error())
			} else {
				problem(w, 401, "authentication_required")
			}
			return
		}
		max := int64(65536)
		if upload {
			max = h.max
		}
		if r.ContentLength > max {
			failure(w, media.ErrTooLarge)
			return
		}
		if r.Body == nil {
			r.Body = http.NoBody
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
		return bodyError(e)
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return bodyError(err)
	}
	return nil
}
func bodyError(e error) error {
	var limit *http.MaxBytesError
	if errors.As(e, &limit) {
		return media.ErrTooLarge
	}
	return media.ErrInput
}

type reviewWriter struct {
	http.ResponseWriter
	started bool
}

func (w *reviewWriter) Write(b []byte) (int, error) {
	w.started = true
	return w.ResponseWriter.Write(b)
}
func empty(r *http.Request) error {
	b, e := io.ReadAll(r.Body)
	if e != nil {
		return bodyError(e)
	}
	if len(b) > 0 {
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
	}{{media.ErrTooLarge, 413}, {media.ErrInput, 400}, {media.ErrDenied, 403}, {media.ErrNotFound, 404}, {media.ErrConflict, 409}, {media.ErrExpired, 410}, {media.ErrIntegrity, 422}, {media.ErrType, 422}, {media.ErrCapacity, 503}} {
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

type downloadWriter struct {
	http.ResponseWriter
	version media.Version
	started bool
}

func (w *downloadWriter) Write(b []byte) (int, error) {
	if !w.started {
		w.Header().Set("Content-Type", w.version.ContentType)
		w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": w.version.Filename}))
		w.Header().Set("Content-Length", strconv.FormatInt(w.version.Size, 10))
		w.WriteHeader(200)
		w.started = true
	}
	return w.ResponseWriter.Write(b)
}
func (h *handler) download(w http.ResponseWriter, r *http.Request, p media.Principal) (any, error) {
	v, e := h.s.ReferenceVersion(r.Context(), p, r.PathValue("id"))
	if e != nil {
		return nil, e
	}
	dst := &downloadWriter{ResponseWriter: w, version: v}
	e = h.s.Download(r.Context(), p, r.PathValue("id"), dst)
	if e != nil && dst.started {
		panic(http.ErrAbortHandler)
	}
	return nil, e
}

type archiveWriter struct {
	http.ResponseWriter
	started bool
}

func (w *archiveWriter) Write(b []byte) (int, error) {
	if !w.started {
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", `attachment; filename="files.zip"`)
		w.WriteHeader(200)
		w.started = true
	}
	return w.ResponseWriter.Write(b)
}
