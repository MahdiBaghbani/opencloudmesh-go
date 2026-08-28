// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// Package webdav provides WebDAV file serving with OCM Bearer auth and read-only behavior.
package webdav

import (
	"context"
	"crypto/subtle"
	"fmt"
	"log/slog"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/net/webdav"

	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
)

// ShareAccessObserver runs after an authorized GET for a resolved outgoing
// share, before the file is served. A non-nil error suppresses the serve in
// favor of a retryable error, so the client's retry re-enters the observer.
// A nil observer keeps the plain product path.
type ShareAccessObserver func(ctx context.Context, share *sharesoutgoing.OutgoingShare) error

// Handler provides WebDAV access to shared files.
type Handler struct {
	outgoingRepo        sharesoutgoing.OutgoingShareRepo
	tokenStore          token.TokenStore
	logger              *slog.Logger
	shareAccessObserver ShareAccessObserver
}

// NewHandler builds a WebDAV handler.
func NewHandler(outgoingRepo sharesoutgoing.OutgoingShareRepo, tokenStore token.TokenStore, logger *slog.Logger) *Handler {
	logger = logutil.NoopIfNil(logger)

	return &Handler{
		outgoingRepo: outgoingRepo,
		tokenStore:   tokenStore,
		logger:       logger,
	}
}

// SetShareAccessObserver installs the optional authorized-GET observer.
func (h *Handler) SetShareAccessObserver(observer ShareAccessObserver) {
	h.shareAccessObserver = observer
}

// ServeHTTP handles WebDAV requests at /webdav/ocm/{webdavId}.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	webdavID := extractWebDAVID(r.URL.Path)
	if webdavID == "" {
		h.logger.Debug("WebDAV request missing webdav_id", "path", r.URL.Path)
		http.Error(w, "webdavId required", http.StatusBadRequest)

		return
	}

	if !isValidWebDAVID(webdavID) {
		h.logger.Debug("WebDAV request with invalid webdav_id", "webdav_id", webdavID)
		http.Error(w, "invalid webdavId", http.StatusBadRequest)

		return
	}

	if isWriteMethod(r.Method) {
		h.logger.Debug("WebDAV write method rejected", "method", r.Method, "webdav_id", webdavID)
		http.Error(w, "write operations not supported", http.StatusNotImplemented)

		return
	}

	cred := extractCredential(r)
	if cred == nil {
		h.logger.Debug("WebDAV request missing authorization", "webdav_id", webdavID)
		w.Header().Set("WWW-Authenticate", `Bearer realm="OCM WebDAV"`)
		http.Error(w, "authorization required", http.StatusUnauthorized)

		return
	}

	h.logger.Debug("WebDAV auth attempt", "webdav_id", webdavID)

	share, err := h.outgoingRepo.GetByWebDAVID(r.Context(), webdavID)
	if err != nil {
		h.logger.Debug("WebDAV share not found", "webdav_id", webdavID)
		http.Error(w, "not found", http.StatusNotFound)

		return
	}

	authorized := h.validateCredential(r.Context(), share, cred.Token)
	if !authorized {
		h.logger.Debug("WebDAV invalid credentials", "webdav_id", webdavID)
		w.Header().Set("WWW-Authenticate", `Bearer realm="OCM WebDAV"`)
		http.Error(w, "invalid credentials", http.StatusUnauthorized)

		return
	}

	h.logger.Debug("WebDAV authorized", "webdav_id", webdavID)

	if r.Method == http.MethodGet && h.shareAccessObserver != nil {
		if err := h.shareAccessObserver(r.Context(), share); err != nil {
			h.logger.Error("WebDAV share access observer failed", "webdav_id", webdavID, "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)

			return
		}
	}

	h.serveFile(w, r, share)
}

// validateCredential validates the token via the token store, or accepts the
// shared secret as a legacy bearer for non-strict shares.
func (h *Handler) validateCredential(ctx context.Context, share *sharesoutgoing.OutgoingShare, token string) bool {
	if h.tokenStore == nil {
		return false
	}

	issuedToken, err := h.tokenStore.Get(ctx, token)
	if err == nil && issuedToken != nil && issuedToken.ShareID == share.ShareID {
		return true
	}

	// Legacy shared-secret bearer is sanctioned for shares that do not
	// require token exchange.
	if !shareRequires(share.Requirements, spec.RequirementMustExchangeToken) &&
		subtle.ConstantTimeCompare([]byte(token), []byte(share.SharedSecret)) == 1 {
		return true
	}

	return false
}

// shareRequires reports whether reqs contains the given requirement.
func shareRequires(reqs []string, req string) bool {
	return slices.Contains(reqs, req)
}

// serveFile serves share.LocalPath via WebDAV.
func (h *Handler) serveFile(w http.ResponseWriter, r *http.Request, share *sharesoutgoing.OutgoingShare) {
	localPath := share.LocalPath

	//nolint:gosec // localPath is repository-controlled via sanitized webdavID lookup, not request-derived input
	stat, err := os.Stat(localPath)
	if err != nil {
		h.logger.Error("WebDAV file stat failed", "path", localPath, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)

		return
	}

	singleFS := &singleFileFS{
		path: localPath,
		info: stat,
	}

	davHandler := &webdav.Handler{
		Prefix:     strings.TrimSuffix(r.URL.Path, "/"+filepath.Base(localPath)),
		FileSystem: singleFS,
		LockSystem: webdav.NewMemLS(),
		Logger: func(r *http.Request, err error) {
			if err != nil {
				h.logger.Debug("WebDAV operation", "method", r.Method, "error", err)
			}
		},
	}

	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		if ct := mime.TypeByExtension(filepath.Ext(localPath)); ct != "" {
			w.Header().Set("Content-Type", ct)
		}
	}

	davHandler.ServeHTTP(w, r)
}

// extractWebDAVID extracts webdavId from path /webdav/ocm/{webdavId} or /webdav/ocm/{webdavId}/...
func extractWebDAVID(path string) string {
	prefix := "/webdav/ocm/"
	if !strings.HasPrefix(path, prefix) {
		return ""
	}

	rest := strings.TrimPrefix(path, prefix)
	if rest == "" {
		return ""
	}

	parts := strings.SplitN(rest, "/", 2)
	if len(parts) == 0 {
		return ""
	}

	return parts[0]
}

// isValidWebDAVID validates webdavID (UUID format, no path traversal).
func isValidWebDAVID(id string) bool {
	if hasDangerousWebDAVChars(id) || len(id) != 36 {
		return false
	}

	return isValidUUIDFormat(id)
}

func hasDangerousWebDAVChars(id string) bool {
	return strings.Contains(id, "..") || strings.Contains(id, "/") || strings.Contains(id, "\\")
}

func isValidUUIDFormat(id string) bool {
	if id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' {
		return false
	}

	for i, c := range id {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue
		}

		if !isHexDigit(c) {
			return false
		}
	}

	return true
}

func isHexDigit(c rune) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// isWriteMethod returns true if the HTTP method is a write operation.
func isWriteMethod(method string) bool {
	switch method {
	case http.MethodPut, http.MethodDelete, "MKCOL", "MOVE", "COPY", "PROPPATCH":
		return true
	}

	return false
}

// credentialResult holds extracted Bearer credentials.
type credentialResult struct {
	Token string
}

// extractCredential extracts auth from a Bearer Authorization header.
func extractCredential(r *http.Request) *credentialResult {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return nil
	}

	if after, ok := strings.CutPrefix(auth, "Bearer "); ok {
		token := after
		if token != "" {
			return &credentialResult{Token: token}
		}
	}

	return nil
}

// singleFileFS implements webdav.FileSystem for a single file. The webdavId
// resource root is the shared file itself; any trailing URL name is cosmetic
// metadata (e.g. the share display name) and must never be used for filesystem
// lookup. Only fs.path / share.LocalPath is opened.
type singleFileFS struct {
	path string
	info os.FileInfo
}

func (fs *singleFileFS) Mkdir(_ context.Context, _ string, _ os.FileMode) error {
	return os.ErrPermission
}

func (fs *singleFileFS) OpenFile(_ context.Context, _ string, flag int, _ os.FileMode) (webdav.File, error) {
	if flag&(os.O_WRONLY|os.O_RDWR|os.O_APPEND|os.O_CREATE|os.O_TRUNC) != 0 {
		return nil, os.ErrPermission
	}

	f, err := os.Open(fs.path)
	if err != nil {
		return nil, fmt.Errorf("webdav: open webdav file: %w", err)
	}

	return f, nil
}

func (fs *singleFileFS) RemoveAll(_ context.Context, _ string) error {
	return os.ErrPermission
}

func (fs *singleFileFS) Rename(_ context.Context, _, _ string) error {
	return os.ErrPermission
}

func (fs *singleFileFS) Stat(_ context.Context, _ string) (os.FileInfo, error) {
	return fs.info, nil
}
