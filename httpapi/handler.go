// Package httpapi exposes authenticated file operations without provider details.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	media "github.com/StuHelper/stuhelper-media"
	"github.com/StuHelper/stuhelper-media/sdk"
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
	upload := pattern == "PUT /api/v1/media/uploads/{id}/content" || pattern == "PATCH /api/v1/media/uploads/{id}/content"
	m.ServeMux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		ctx, cancel := context.WithTimeout(r.Context(), m.h.s.OperationTimeout())
		defer cancel()
		if trace := r.Header.Get("Traceparent"); trace != "" {
			ctx = media.WithTraceID(ctx, trace)
		} else if id := r.Header.Get("X-Request-Id"); id != "" {
			ctx = media.WithTraceID(ctx, id)
		}
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

func (h *handler) ListProfiles(w http.ResponseWriter, r *http.Request) {
	if len(r.URL.Query()) != 0 {
		h.respond(w, r, nil, media.ErrInput)
		return
	}
	out, e := h.s.ListProfiles(r.Context(), principalOf(r))
	h.respond(w, r, out, e)
}
func (h *handler) GetUploadIntake(w http.ResponseWriter, r *http.Request, purpose string, params sdk.GetUploadIntakeParams) {
	if len(r.URL.Query()) != 1 || len(r.URL.Query()["size"]) != 1 {
		h.respond(w, r, nil, media.ErrInput)
		return
	}
	out, err := h.s.UploadIntake(r.Context(), principalOf(r), purpose, params.Size)
	h.respond(w, r, out, err)
}
func (h *handler) AppendUploadContent(w http.ResponseWriter, r *http.Request, id string, params sdk.AppendUploadContentParams) {
	typ, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || typ != "application/octet-stream" || len(r.Header.Values("Upload-Offset")) != 1 || params.UploadOffset < 0 {
		h.respond(w, r, nil, media.ErrInput)
		return
	}
	out, e := h.s.AppendUpload(r.Context(), principalOf(r), id, params.IdempotencyKey, params.UploadOffset, r.Body)
	h.respond(w, r, out, e)
}
func (h *handler) GetOperations(w http.ResponseWriter, r *http.Request, params sdk.GetOperationsParams) {
	for name, values := range r.URL.Query() {
		if len(values) != 1 || (name != "limit" && name != "failures_after") {
			h.respond(w, r, nil, media.ErrInput)
			return
		}
	}
	limit := 50
	if params.Limit != nil {
		limit = *params.Limit
	}
	out, e := h.s.Operations(r.Context(), principalOf(r), limit, r.URL.Query().Get("failures_after"))
	h.respond(w, r, out, e)
}
func (h *handler) RetryJob(w http.ResponseWriter, r *http.Request, id string, params sdk.RetryJobParams) {
	var req media.RetryJobRequest
	if e := decode(r, &req); e != nil {
		h.respond(w, r, nil, e)
		return
	}
	out, e := h.s.RetryJob(r.Context(), principalOf(r), id, params.IdempotencyKey, req.Generation)
	h.respond(w, r, out, e)
}
func (h *handler) PruneHistory(w http.ResponseWriter, r *http.Request) {
	var req media.PruneRequest
	if e := decode(r, &req); e != nil {
		h.respond(w, r, nil, e)
		return
	}
	out, e := h.s.PruneAs(r.Context(), principalOf(r), req.Limit)
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
		if len(values) != 1 || (name != "limit" && name != "cursor" && name != "purpose" && name != "state") {
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
	out, e := h.s.ListFilesFiltered(r.Context(), principalOf(r), media.FileListFilter{Limit: limit, Cursor: cursor, Purpose: r.URL.Query().Get("purpose"), State: r.URL.Query().Get("state")})
	h.respond(w, r, out, e)
}

func (h *handler) ArchiveManifest(w http.ResponseWriter, r *http.Request) {
	var q media.ArchiveRequest
	if e := decode(r, &q); e != nil {
		h.respond(w, r, nil, e)
		return
	}
	if _, e := media.SanitizeArchiveFilename(q.Filename); e != nil {
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
	archiveName, e := media.SanitizeArchiveFilename(q.Filename)
	if e != nil {
		h.respond(w, r, nil, e)
		return
	}
	dst := &archiveWriter{ResponseWriter: w, filename: archiveName}
	e = h.s.Archive(r.Context(), principalOf(r), q.References, dst)
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

func (h *handler) RejectVersion(w http.ResponseWriter, r *http.Request, id string, params sdk.RejectVersionParams) {
	var q media.RejectionRequest
	if e := decode(r, &q); e != nil {
		h.respond(w, r, nil, e)
		return
	}
	out, e := h.s.Reject(r.Context(), principalOf(r), id, params.IdempotencyKey, q.Reason)
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
		{media.ErrReplicaShortage, 503, 0},
		{media.ErrReplicaSpace, 503, 0},
		{media.ErrRestrictedUnavailable, 503, 0},
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

func (h *handler) HeadReference(w http.ResponseWriter, r *http.Request, id string, _ sdk.HeadReferenceParams) {
	p := principalOf(r)
	disposition, e := parseDispositionQuery(r)
	if e != nil {
		h.respond(w, r, nil, e)
		return
	}
	v, e := h.s.InspectReferenceDownload(r.Context(), p, id)
	if e != nil {
		h.respond(w, r, nil, e)
		return
	}
	etag := `"` + v.SHA256 + `"`
	if ifNoneMatch(r.Header.Get("If-None-Match"), etag) {
		w.Header().Set("ETag", etag)
		w.Header().Set("Accept-Ranges", "bytes")
		w.Header().Set("Cache-Control", "private, no-cache")
		w.WriteHeader(http.StatusNotModified)
		return
	}
	applyContentHeaders(w, v, disposition)
	w.Header().Set("Content-Length", strconv.FormatInt(v.Size, 10))
	w.WriteHeader(http.StatusOK)
	return
}

func (h *handler) DownloadReference(w http.ResponseWriter, r *http.Request, id string, _ sdk.DownloadReferenceParams) {
	p := principalOf(r)
	disposition, e := parseDispositionQuery(r)
	if e != nil {
		h.respond(w, r, nil, e)
		return
	}
	v, e := h.s.InspectReferenceDownload(r.Context(), p, id)
	if e != nil {
		h.respond(w, r, nil, e)
		return
	}
	etag := `"` + v.SHA256 + `"`
	if ifNoneMatch(r.Header.Get("If-None-Match"), etag) {
		w.Header().Set("ETag", etag)
		w.Header().Set("Accept-Ranges", "bytes")
		w.Header().Set("Cache-Control", "private, no-cache")
		w.WriteHeader(http.StatusNotModified)
		return
	}
	partial, start, end, unsatisfiable := parseByteRange(r.Header.Get("Range"), r.Header.Get("If-Range"), etag, v.Size)
	if unsatisfiable {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", v.Size))
		problem(w, http.StatusRequestedRangeNotSatisfiable, media.ErrInput.Error())
		return
	}
	dst := &downloadWriter{
		ResponseWriter: w,
		version:        v,
		disposition:    disposition,
		partial:        partial,
		rangeStart:     start,
		rangeEnd:       end,
	}
	e = h.s.Download(r.Context(), p, id, dst)
	if e != nil && dst.started {
		panic(http.ErrAbortHandler)
	}
	h.respond(w, r, nil, e)
	return
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
