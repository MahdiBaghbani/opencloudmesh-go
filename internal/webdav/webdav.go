// Package webdav provides a minimal WebDAV handler for OCM file serving.
// It wraps golang.org/x/net/webdav with OCM-specific auth and read-only behavior.
package webdav

import (
	"context"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/ocm/shares"
	"golang.org/x/net/webdav"
)

// Handler provides WebDAV access to shared files.
type Handler struct {
	outgoingRepo shares.OutgoingShareRepo
	logger       *slog.Logger
}

// NewHandler creates a new WebDAV handler.
func NewHandler(outgoingRepo shares.OutgoingShareRepo, logger *slog.Logger) *Handler {
	return &Handler{
		outgoingRepo: outgoingRepo,
		logger:       logger,
	}
}

// ServeHTTP handles WebDAV requests at /webdav/ocm/{webdavId}.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Extract webdavId from path
	// Path format: /webdav/ocm/{webdavId} or /webdav/ocm/{webdavId}/...
	webdavID := extractWebDAVID(r.URL.Path)
	if webdavID == "" {
		h.logger.Debug("WebDAV request missing webdavId", "path", r.URL.Path)
		http.Error(w, "webdavId required", http.StatusBadRequest)
		return
	}

	// Validate webdavId format (should be a UUID)
	if !isValidWebDAVID(webdavID) {
		h.logger.Debug("WebDAV request with invalid webdavId", "webdavId", webdavID)
		http.Error(w, "invalid webdavId", http.StatusBadRequest)
		return
	}

	// Check for write methods and reject with 501
	if isWriteMethod(r.Method) {
		h.logger.Debug("WebDAV write method rejected", "method", r.Method, "webdavId", webdavID)
		http.Error(w, "write operations not supported", http.StatusNotImplemented)
		return
	}

	// Extract and validate bearer token
	secret := extractBearerToken(r)
	if secret == "" {
		h.logger.Debug("WebDAV request missing authorization", "webdavId", webdavID)
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "authorization required", http.StatusUnauthorized)
		return
	}

	// Look up share by webdavId
	share, err := h.outgoingRepo.GetByWebDAVID(r.Context(), webdavID)
	if err != nil {
		h.logger.Debug("WebDAV share not found", "webdavId", webdavID)
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	// Validate shared secret
	if share.SharedSecret != secret {
		h.logger.Debug("WebDAV invalid secret", "webdavId", webdavID)
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	// Serve the file using webdav package
	h.serveFile(w, r, share)
}

// serveFile serves the file at share.LocalPath via WebDAV.
func (h *Handler) serveFile(w http.ResponseWriter, r *http.Request, share *shares.OutgoingShare) {
	// Create a file system rooted at the file's parent directory
	localPath := share.LocalPath

	// Check if the file exists
	stat, err := os.Stat(localPath)
	if err != nil {
		h.logger.Error("WebDAV file stat failed", "path", localPath, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Create a single-file filesystem
	singleFS := &singleFileFS{
		path: localPath,
		info: stat,
	}

	// Create webdav handler for this file
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

// extractWebDAVID extracts the webdavId from the request path.
// Expected path format: /webdav/ocm/{webdavId}
func extractWebDAVID(path string) string {
	// Strip prefix /webdav/ocm/
	prefix := "/webdav/ocm/"
	if !strings.HasPrefix(path, prefix) {
		return ""
	}

	rest := strings.TrimPrefix(path, prefix)
	if rest == "" {
		return ""
	}

	// Get the first path segment as webdavId
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) == 0 {
		return ""
	}

	return parts[0]
}

// isValidWebDAVID validates a webdavId (should be a UUID format).
func isValidWebDAVID(id string) bool {
	// Check for path traversal
	if strings.Contains(id, "..") || strings.Contains(id, "/") || strings.Contains(id, "\\") {
		return false
	}

	// Basic UUID format check (8-4-4-4-12 hex digits)
	if len(id) != 36 {
		return false
	}

	// Check hyphens at correct positions
	if id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' {
		return false
	}

	// Check all other chars are hex
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

// extractBearerToken extracts the bearer token from the Authorization header.
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

// singleFileFS implements webdav.FileSystem for serving a single file.
type singleFileFS struct {
	path string
	info fs.FileInfo
}

func (fs *singleFileFS) Mkdir(ctx context.Context, name string, perm os.FileMode) error {
	return os.ErrPermission
}

func (fs *singleFileFS) OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (webdav.File, error) {
	// Only allow opening the root or the file itself
	name = strings.TrimPrefix(name, "/")
	if name != "" && name != filepath.Base(fs.path) {
		return nil, os.ErrNotExist
	}

	// If opening root, return a virtual directory containing the file
	if name == "" {
		return &virtualDir{
			name:  "/",
			files: []os.FileInfo{fs.info},
		}, nil
	}

	// Open the actual file (read-only)
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
		// Return info for the virtual root directory
		return &virtualDirInfo{name: "/"}, nil
	}
	if name == filepath.Base(fs.path) {
		return fs.info, nil
	}
	return nil, os.ErrNotExist
}

// virtualDir represents a virtual directory containing a single file.
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

// virtualDirInfo represents info for a virtual directory.
type virtualDirInfo struct {
	name string
}

func (i *virtualDirInfo) Name() string       { return i.name }
func (i *virtualDirInfo) Size() int64        { return 0 }
func (i *virtualDirInfo) Mode() os.FileMode  { return os.ModeDir | 0555 }
func (i *virtualDirInfo) ModTime() time.Time { return time.Now() }
func (i *virtualDirInfo) IsDir() bool        { return true }
func (i *virtualDirInfo) Sys() interface{}   { return nil }
