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
		ctx, cancel := context.WithTimeout(r.Context(), m.h.s.OperationTimeout())
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
		p, e := m.h.auth.Authenticate(r)
		if e != nil || !p.Valid() {
			if errors.Is(e, media.ErrUnavailable) {
				problem(w, 503, media.ErrUnavailable.Error())
			} else {
				problem(w, 401, "authentication_required")
			}
			return
		}
		limit := int64(65536)
		if upload {
			limit = m.h.max
		}
		if r.ContentLength > limit {
			w.Header().Set("Connection", "close")
			failure(w, &http.MaxBytesError{Limit: limit})
			return
		}
		raw := r.Body
		if raw == nil {
			raw = http.NoBody
		}
		if len(r.Header.Values("Idempotency-Key")) > 1 {
			failure(w, media.ErrInput)
			return
		}
		tracked := &trackedBody{ReadCloser: http.MaxBytesReader(w, raw, limit)}
		r = r.WithContext(context.WithValue(r.Context(), requestKey{}, requestState{principal: p, body: tracked}))
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
	generated := sdk.HandlerWithOptions(h, sdk.StdHTTPServerOptions{
		BaseRouter: mux,
		ErrorHandlerFunc: func(w http.ResponseWriter, _ *http.Request, _ error) {
			problem(w, 400, media.ErrInput.Error())
		},
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler, pattern := mux.Handler(r)
		if pattern == "" {
			handler.ServeHTTP(routeErrorWriter{w}, r)
			return
		}
		generated.ServeHTTP(w, r)
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

func (h *handler) DownloadReviewContent(w http.ResponseWriter, r *http.Request, id string) {
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment")
	dst := &reviewWriter{ResponseWriter: w}
	err := h.s.ReviewDownload(r.Context(), principalOf(r), id, dst)
	if err != nil && dst.started {
		panic(http.ErrAbortHandler)
	}
	h.respond(w, r, nil, err)
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

type problemBody struct {
	Code              string `json:"code"`
	Limit             *int64 `json:"limit,omitempty"`
	RetryAfterSeconds *int64 `json:"retry_after_seconds,omitempty"`
}

func problem(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, problemBody{Code: code})
}

func failure(w http.ResponseWriter, e error) {
	status, code := 503, media.ErrUnavailable.Error()
	var retryAfter int64
	for _, entry := range []struct {
		e          error
		status     int
		retryAfter int64
	}{
		{media.ErrFilenameInvalid, 400, 0},
		{media.ErrTypeNotAllowed, 400, 0},
		{media.ErrUploadTooLarge, 413, 0},
		{media.ErrInput, 400, 0},
		{media.ErrDenied, 403, 0},
		{media.ErrNotFound, 404, 0},
		{media.ErrFileLimit, 409, 0},
		{media.ErrVersionLimit, 409, 0},
		{media.ErrReferenceLimit, 409, 0},
		{media.ErrConflict, 409, 0},
		{media.ErrExpired, 410, 0},
		{media.ErrArchiveTooLarge, 413, 0},
		{media.ErrIntegrity, 422, 0},
		{media.ErrType, 422, 0},
		{media.ErrOpenUploadsLimit, 429, 0},
		{media.ErrTransferBusy, 503, 3},
		{media.ErrCapacity, 503, 5},
	} {
		if errors.Is(e, entry.e) {
			status = entry.status
			code = entry.e.Error()
			retryAfter = entry.retryAfter
			break
		}
	}
	out := problemBody{Code: code}
	if limit, ok := media.ErrorLimit(e); ok {
		out.Limit = &limit
	}
	var maxErr *http.MaxBytesError
	if errors.As(e, &maxErr) {
		status = 413
		code = media.ErrUploadTooLarge.Error()
		out.Code = code
		if maxErr.Limit > 0 {
			lim := maxErr.Limit
			out.Limit = &lim
		}
		retryAfter = 0
	}
	if retryAfter > 0 {
		w.Header().Set("Retry-After", strconv.FormatInt(retryAfter, 10))
		out.RetryAfterSeconds = &retryAfter
	}
	writeJSON(w, status, out)
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
