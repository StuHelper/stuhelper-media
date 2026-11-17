// Package httpapi exposes authenticated file operations without provider details.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	media "github.com/StuHelper/stuhelper-media"
	"github.com/StuHelper/stuhelper-media/sdk"
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

var _ sdk.ServerInterface = (*handler)(nil)

type requestKey struct{}

type requestState struct {
	principal media.Principal
	body      *trackedBody
}

type trackedBody struct {
	io.ReadCloser
	exceeded *http.MaxBytesError
}

func (b *trackedBody) Read(p []byte) (int, error) {
	n, e := b.ReadCloser.Read(p)
	if e != nil {
		errors.As(e, &b.exceeded)
	}
	return n, e
}

type authMux struct {
	*http.ServeMux
	h *handler
}

func (m *authMux) HandleFunc(pattern string, next func(http.ResponseWriter, *http.Request)) {
	upload := pattern == http.MethodPut+" /api/v1/media/uploads/{id}/content"
	m.ServeMux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		p, e := m.h.auth.Authenticate(r)
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
		controller := http.NewResponseController(w)
		deadline, _ := ctx.Deadline()
		_ = controller.SetReadDeadline(deadline)
		_ = controller.SetWriteDeadline(deadline)
		stop := context.AfterFunc(ctx, func() {
			_ = controller.SetReadDeadline(time.Now())
			_ = controller.SetWriteDeadline(time.Now())
		})
		defer stop()
		limit := int64(65536)
		if upload {
			limit = m.h.max
		}
		if r.ContentLength > limit {
			w.Header().Set("Connection", "close")
			problem(w, 413, "media_upload_too_large")
			return
		}
		raw := r.Body
		if raw == nil {
			raw = http.NoBody
		}
		maxBytes := limit
		if upload {
			maxBytes = m.h.max + 1
		}
		tracked := &trackedBody{ReadCloser: http.MaxBytesReader(w, raw, maxBytes)}
		r = r.WithContext(context.WithValue(ctx, requestKey{}, requestState{principal: p, body: tracked}))
		r.Body = tracked
		next(w, r)
	})
}

func New(s *media.Service, a Authenticator, max int64) (http.Handler, error) {
	if s == nil || a == nil || max < 1 || max > 1<<30 {
		return nil, media.ErrInput
	}
	h := &handler{s: s, auth: a, max: max}
	mux := &authMux{ServeMux: http.NewServeMux(), h: h}
	return sdk.HandlerWithOptions(h, sdk.StdHTTPServerOptions{
		BaseRouter: mux,
		ErrorHandlerFunc: func(w http.ResponseWriter, _ *http.Request, _ error) {
			problem(w, 400, media.ErrInput.Error())
		},
	}), nil
}

func principalOf(r *http.Request) media.Principal {
	if st, ok := r.Context().Value(requestKey{}).(requestState); ok {
		return st.principal
	}
	return media.Principal{}
}

func (h *handler) respond(w http.ResponseWriter, r *http.Request, out any, e error) {
	if e != nil {
		if st, ok := r.Context().Value(requestKey{}).(requestState); ok && st.body != nil && st.body.exceeded != nil {
			e = st.body.exceeded
		}
		failure(w, e)
		return
	}
	if out != nil {
		writeJSON(w, 200, out)
	}
}

func (h *handler) CreateUpload(w http.ResponseWriter, r *http.Request, params sdk.CreateUploadParams) {
	var q media.UploadRequest
	if e := decode(r, &q); e != nil {
		h.respond(w, r, nil, e)
		return
	}
	out, e := h.s.CreateUpload(r.Context(), principalOf(r), params.IdempotencyKey, q)
	h.respond(w, r, out, e)
}

func (h *handler) GetUpload(w http.ResponseWriter, r *http.Request, id string) {
	out, e := h.s.GetUpload(r.Context(), principalOf(r), id)
	h.respond(w, r, out, e)
}

func (h *handler) CancelUpload(w http.ResponseWriter, r *http.Request, id string, params sdk.CancelUploadParams) {
	if e := empty(r); e != nil {
		h.respond(w, r, nil, e)
		return
	}
	out, e := h.s.CancelUpload(r.Context(), principalOf(r), id, params.IdempotencyKey)
	h.respond(w, r, out, e)
}

func (h *handler) UploadContent(w http.ResponseWriter, r *http.Request, id string, params sdk.UploadContentParams) {
	typ, _, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if e != nil || typ != "application/octet-stream" {
		h.respond(w, r, nil, media.ErrInput)
		return
	}
	out, e := h.s.Upload(r.Context(), principalOf(r), id, params.IdempotencyKey, r.Body)
	h.respond(w, r, out, e)
}

func (h *handler) ListFiles(w http.ResponseWriter, r *http.Request, params sdk.ListFilesParams) {
	for name, values := range r.URL.Query() {
		if len(values) != 1 || (name != "limit" && name != "cursor") {
			h.respond(w, r, nil, media.ErrInput)
			return
		}
	}
	limit := 50
	if params.Limit != nil {
		limit = *params.Limit
	}
	cursor := ""
	if params.Cursor != nil {
		cursor = *params.Cursor
	}
	out, e := h.s.ListFiles(r.Context(), principalOf(r), limit, cursor)
	h.respond(w, r, out, e)
}

func (h *handler) ArchiveManifest(w http.ResponseWriter, r *http.Request) {
	var q media.ArchiveRequest
	if e := decode(r, &q); e != nil {
		h.respond(w, r, nil, e)
		return
	}
	out, e := h.s.ArchiveManifest(r.Context(), principalOf(r), q.References)
	h.respond(w, r, out, e)
}

func (h *handler) DownloadArchive(w http.ResponseWriter, r *http.Request) {
	var q media.ArchiveRequest
	if e := decode(r, &q); e != nil {
		h.respond(w, r, nil, e)
		return
	}
	dst := &archiveWriter{ResponseWriter: w}
	e := h.s.Archive(r.Context(), principalOf(r), q.References, dst)
	if e != nil && dst.started {
		panic(http.ErrAbortHandler)
	}
	h.respond(w, r, nil, e)
}

func (h *handler) GetFile(w http.ResponseWriter, r *http.Request, id string) {
	out, e := h.s.GetFile(r.Context(), principalOf(r), id)
	h.respond(w, r, out, e)
}

func (h *handler) DeleteFile(w http.ResponseWriter, r *http.Request, id string, params sdk.DeleteFileParams) {
	var q sdk.Revision
	if e := decode(r, &q); e != nil {
		h.respond(w, r, nil, e)
		return
	}
	out, e := h.s.DeleteFile(r.Context(), principalOf(r), id, params.IdempotencyKey, q.Revision)
	h.respond(w, r, out, e)
}

func (h *handler) SetFileState(w http.ResponseWriter, r *http.Request, id string, params sdk.SetFileStateParams) {
	var q sdk.FileState
	if e := decode(r, &q); e != nil {
		h.respond(w, r, nil, e)
		return
	}
	out, e := h.s.SetFileState(r.Context(), principalOf(r), id, params.IdempotencyKey, q.Revision, q.Disabled)
	h.respond(w, r, out, e)
}

func (h *handler) GetVersion(w http.ResponseWriter, r *http.Request, id string) {
	out, e := h.s.GetVersion(r.Context(), principalOf(r), id)
	h.respond(w, r, out, e)
}

func (h *handler) ApproveVersion(w http.ResponseWriter, r *http.Request, id string, params sdk.ApproveVersionParams) {
	if e := empty(r); e != nil {
		h.respond(w, r, nil, e)
		return
	}
	out, e := h.s.Approve(r.Context(), principalOf(r), id, params.IdempotencyKey)
	h.respond(w, r, out, e)
}

func (h *handler) AttachReference(w http.ResponseWriter, r *http.Request, id string, params sdk.AttachReferenceParams) {
	var q media.Binding
	if e := decode(r, &q); e != nil {
		h.respond(w, r, nil, e)
		return
	}
	out, e := h.s.Attach(r.Context(), principalOf(r), id, params.IdempotencyKey, q)
	h.respond(w, r, out, e)
}

func (h *handler) GetReference(w http.ResponseWriter, r *http.Request, id string) {
	out, e := h.s.GetReference(r.Context(), principalOf(r), id)
	h.respond(w, r, out, e)
}

func (h *handler) ReleaseReference(w http.ResponseWriter, r *http.Request, id string, params sdk.ReleaseReferenceParams) {
	if e := empty(r); e != nil {
		h.respond(w, r, nil, e)
		return
	}
	out, e := h.s.Release(r.Context(), principalOf(r), id, params.IdempotencyKey)
	h.respond(w, r, out, e)
}

func (h *handler) PublishReference(w http.ResponseWriter, r *http.Request, id string, params sdk.PublishReferenceParams) {
	if e := empty(r); e != nil {
		h.respond(w, r, nil, e)
		return
	}
	out, e := h.s.Publish(r.Context(), principalOf(r), id, params.IdempotencyKey)
	h.respond(w, r, out, e)
}

func (h *handler) DownloadReference(w http.ResponseWriter, r *http.Request, id string) {
	p := principalOf(r)
	v, e := h.s.ReferenceVersion(r.Context(), p, id)
	if e != nil {
		h.respond(w, r, nil, e)
		return
	}
	dst := &downloadWriter{ResponseWriter: w, version: v}
	e = h.s.Download(r.Context(), p, id, dst)
	if e != nil && dst.started {
		panic(http.ErrAbortHandler)
	}
	h.respond(w, r, nil, e)
}

func decode(r *http.Request, out any) error {
	typ, _, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if e != nil || typ != "application/json" {
		return media.ErrInput
	}
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if e = d.Decode(out); e != nil {
		var limit *http.MaxBytesError
		if errors.As(e, &limit) {
			return e
		}
		return media.ErrInput
	}
	if e = d.Decode(new(any)); e != io.EOF {
		var limit *http.MaxBytesError
		if errors.As(e, &limit) {
			return e
		}
		return media.ErrInput
	}
	return nil
}

func empty(r *http.Request) error {
	b, e := io.ReadAll(io.LimitReader(r.Body, 1))
	if e != nil {
		var limit *http.MaxBytesError
		if errors.As(e, &limit) {
			return e
		}
		return media.ErrInput
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
