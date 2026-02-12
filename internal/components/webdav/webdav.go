// Package webdav provides WebDAV file serving with OCM auth (Bearer/Basic) and read-only behavior.
package webdav

import (
	"context"
	"encoding/base64"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peercompat"
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
	"golang.org/x/net/webdav"
)

// Handler provides WebDAV access to shared files.
type Handler struct {
	outgoingRepo    sharesoutgoing.OutgoingShareRepo
	tokenStore      token.TokenStore
	settings        *Settings
	profileRegistry *peercompat.ProfileRegistry
	logger          *slog.Logger
}

// NewHandler builds a WebDAV handler. Settings control must-exchange-token enforcement; ProfileRegistry enables peer relaxations in lenient mode.
func NewHandler(outgoingRepo sharesoutgoing.OutgoingShareRepo, tokenStore token.TokenStore, settings *Settings, profileRegistry *peercompat.ProfileRegistry, logger *slog.Logger) *Handler {
	logger = logutil.NoopIfNil(logger)
	if settings == nil {
		settings = &Settings{}
		settings.ApplyDefaults()
	}
	return &Handler{
		outgoingRepo:    outgoingRepo,
		tokenStore:      tokenStore,
		settings:        settings,
		profileRegistry: profileRegistry,
		logger:          logger,
	}
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
		w.Header().Set("WWW-Authenticate", `Bearer, Basic realm="OCM WebDAV"`)
		http.Error(w, "authorization required", http.StatusUnauthorized)
		return
	}

	// Log auth source only - NEVER log the actual token
	h.logger.Debug("WebDAV auth attempt", "webdav_id", webdavID, "auth_source", cred.Source)

	// Look up share by webdavId
	share, err := h.outgoingRepo.GetByWebDAVID(r.Context(), webdavID)
	if err != nil {
		h.logger.Debug("WebDAV share not found", "webdav_id", webdavID)
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	authorized, authMethod := h.validateCredential(r.Context(), share, cred.Token, cred.Source)
	if !authorized {
		h.logger.Debug("WebDAV invalid credentials", "webdav_id", webdavID)
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	h.logger.Debug("WebDAV authorized", "webdav_id", webdavID, "auth_method", authMethod)

	// Serve the file using webdav package
	h.serveFile(w, r, share)
}

// validateCredential validates the token; returns (authorized, method) with method "exchanged_token" or "shared_secret".
func (h *Handler) validateCredential(ctx context.Context, share *sharesoutgoing.OutgoingShare, token string, authSource string) (bool, string) {
	if h.tokenStore != nil {
		issuedToken, err := h.tokenStore.Get(ctx, token)
		if err == nil && issuedToken != nil && issuedToken.ShareID == share.ShareID {
			return true, "exchanged_token"
		}
	}

	profile := h.getProfileForShare(share)

	if strings.HasPrefix(authSource, "basic:") {
		patternKey := strings.TrimPrefix(authSource, "basic:")
		if !profile.IsBasicAuthPatternAllowed(patternKey) {
			return false, ""
		}
	}

	if share.MustExchangeToken && h.settings.EnforceMustExchangeToken() {
		if h.settings.WebDAVTokenExchangeMode == "lenient" && profile.RelaxMustExchangeToken {
		} else {
			return false, ""
		}
	}

	if share.SharedSecret == token {
		return true, "shared_secret"
	}

	return false, ""
}

// getProfileForShare returns the peer profile; falls back to strict if no registry.
func (h *Handler) getProfileForShare(share *sharesoutgoing.OutgoingShare) *peercompat.Profile {
	if h.profileRegistry == nil {
		return peercompat.BuiltinProfiles()["strict"]
	}
	return h.profileRegistry.GetProfile(share.ReceiverHost)
}

// serveFile serves share.LocalPath via WebDAV.
func (h *Handler) serveFile(w http.ResponseWriter, r *http.Request, share *sharesoutgoing.OutgoingShare) {
	localPath := share.LocalPath

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

// isValidWebDAVID validates webdavId (UUID format, no path traversal).
func isValidWebDAVID(id string) bool {
	if strings.Contains(id, "..") || strings.Contains(id, "/") || strings.Contains(id, "\\") {
		return false
	}

	if len(id) != 36 {
		return false
	}

	if id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' {
		return false
	}

	for i, c := range id {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue
		}
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}

	return true
}

// isWriteMethod returns true if the HTTP method is a write operation.
func isWriteMethod(method string) bool {
	switch method {
	case http.MethodPut, http.MethodDelete, "MKCOL", "MOVE", "COPY", "PROPPATCH":
		return true
	}
	return false
}

// credentialResult holds extracted auth credentials.
type credentialResult struct {
	Token  string
	Source string // auth source for logging only (bearer, basic:*, etc)
}

// extractCredential extracts auth from Bearer or Basic header. Returns nil if absent or invalid.
func extractCredential(r *http.Request) *credentialResult {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return nil
	}

	if strings.HasPrefix(auth, "Bearer ") {
		token := strings.TrimPrefix(auth, "Bearer ")
		if token != "" {
			return &credentialResult{Token: token, Source: "bearer"}
		}
		return nil
	}

	if strings.HasPrefix(auth, "Basic ") {
		encoded := strings.TrimPrefix(auth, "Basic ")
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil
		}
		parts := strings.SplitN(string(decoded), ":", 2)
		if len(parts) != 2 {
			return nil
		}
		username, password := parts[0], parts[1]

		if password == "" && username != "" {
			return &credentialResult{Token: username, Source: "basic:token:"}
		}

		if username != "" && username == password {
			return &credentialResult{Token: username, Source: "basic:token:token"}
		}

		if username == "" && password != "" {
			return &credentialResult{Token: password, Source: "basic::token"}
		}

		if username != "" && password != "" {
			token := strings.TrimSuffix(password, ":")
			return &credentialResult{Token: token, Source: "basic:id:token"}
		}

		return nil
	}

	return nil
}

// extractBearerToken returns the Bearer token. Deprecated: use extractCredential.
func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return ""
	}

	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		return ""
	}

	return strings.TrimPrefix(auth, prefix)
}

// singleFileFS implements webdav.FileSystem for a single file.
type singleFileFS struct {
	path string
	info fs.FileInfo
}

func (fs *singleFileFS) Mkdir(ctx context.Context, name string, perm os.FileMode) error {
	return os.ErrPermission
}

func (fs *singleFileFS) OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (webdav.File, error) {
	name = strings.TrimPrefix(name, "/")
	if name != "" && name != filepath.Base(fs.path) {
		return nil, os.ErrNotExist
	}

	if name == "" {
		return &virtualDir{
			name:  "/",
			files: []os.FileInfo{fs.info},
		}, nil
	}

	if flag&(os.O_WRONLY|os.O_RDWR|os.O_APPEND|os.O_CREATE|os.O_TRUNC) != 0 {
		return nil, os.ErrPermission
	}

	return os.Open(fs.path)
}

func (fs *singleFileFS) RemoveAll(ctx context.Context, name string) error {
	return os.ErrPermission
}

func (fs *singleFileFS) Rename(ctx context.Context, oldName, newName string) error {
	return os.ErrPermission
}

func (fs *singleFileFS) Stat(ctx context.Context, name string) (os.FileInfo, error) {
	name = strings.TrimPrefix(name, "/")
	if name == "" {
		return &virtualDirInfo{name: "/"}, nil
	}
	if name == filepath.Base(fs.path) {
		return fs.info, nil
	}
	return nil, os.ErrNotExist
}

// virtualDir is a virtual directory containing a single file.
type virtualDir struct {
	name   string
	files  []os.FileInfo
	offset int
}

func (d *virtualDir) Close() error                             { return nil }
func (d *virtualDir) Read(p []byte) (n int, err error)         { return 0, os.ErrInvalid }
func (d *virtualDir) Write(p []byte) (n int, err error)        { return 0, os.ErrPermission }
func (d *virtualDir) Seek(offset int64, whence int) (int64, error) { return 0, os.ErrInvalid }

func (d *virtualDir) Readdir(count int) ([]os.FileInfo, error) {
	if d.offset >= len(d.files) {
		if count <= 0 {
			return nil, nil
		}
		return nil, io.EOF
	}

	if count <= 0 {
		files := d.files[d.offset:]
		d.offset = len(d.files)
		return files, nil
	}

	end := d.offset + count
	if end > len(d.files) {
		end = len(d.files)
	}
	files := d.files[d.offset:end]
	d.offset = end
	return files, nil
}

func (d *virtualDir) Stat() (os.FileInfo, error) {
	return &virtualDirInfo{name: d.name}, nil
}

// virtualDirInfo is the os.FileInfo for a virtual directory.
type virtualDirInfo struct {
	name string
}

func (i *virtualDirInfo) Name() string       { return i.name }
func (i *virtualDirInfo) Size() int64        { return 0 }
func (i *virtualDirInfo) Mode() os.FileMode  { return os.ModeDir | 0555 }
func (i *virtualDirInfo) ModTime() time.Time { return time.Now() }
func (i *virtualDirInfo) IsDir() bool        { return true }
func (i *virtualDirInfo) Sys() interface{}   { return nil }
