package webdav_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/ocm/shares"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/ocm/token"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/webdav"
)

func TestExtractWebDAVID(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"/webdav/ocm/abc-123", "abc-123"},
		{"/webdav/ocm/550e8400-e29b-41d4-a716-446655440000", "550e8400-e29b-41d4-a716-446655440000"},
		{"/webdav/ocm/", ""},
		{"/webdav/ocm", ""},
		{"/other/path", ""},
		{"/webdav/ocm/id/extra/path", "id"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := webdav.ExtractWebDAVIDForTest(tt.path)
			if result != tt.expected {
				t.Errorf("extractWebDAVID(%q) = %q, want %q", tt.path, result, tt.expected)
			}
		})
	}
}

func TestIsValidWebDAVID(t *testing.T) {
	tests := []struct {
		id    string
		valid bool
	}{
		{"550e8400-e29b-41d4-a716-446655440000", true},
		{"019435c7-9a2a-7e3c-8b0a-123456789abc", true},
		{"../etc/passwd", false},
		{"abc", false},
		{"", false},
		{"550e8400-e29b-41d4-a716-44665544000z", false}, // invalid hex char
	}

	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			result := webdav.IsValidWebDAVIDForTest(tt.id)
			if result != tt.valid {
				t.Errorf("isValidWebDAVID(%q) = %v, want %v", tt.id, result, tt.valid)
			}
		})
	}
}

func TestWriteMethodsRejected(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	repo := shares.NewMemoryOutgoingShareRepo()
	handler := webdav.NewHandler(repo, nil, logger)

	writeMethods := []string{http.MethodPut, http.MethodDelete, "MKCOL", "MOVE", "COPY", "PROPPATCH"}
	
	for _, method := range writeMethods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/webdav/ocm/550e8400-e29b-41d4-a716-446655440000", nil)
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			if w.Code != http.StatusNotImplemented {
				t.Errorf("expected 501 for %s, got %d", method, w.Code)
			}
		})
	}
}

func TestAuthRequired(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	repo := shares.NewMemoryOutgoingShareRepo()
	handler := webdav.NewHandler(repo, nil, logger)

	req := httptest.NewRequest(http.MethodGet, "/webdav/ocm/550e8400-e29b-41d4-a716-446655440000", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}

	if w.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Error("expected WWW-Authenticate: Bearer header")
	}
}

func TestInvalidSecret(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	repo := shares.NewMemoryOutgoingShareRepo()

	// Create a share
	share := &shares.OutgoingShare{
		ProviderID:   "provider-123",
		WebDAVID:     "550e8400-e29b-41d4-a716-446655440000",
		SharedSecret: "correct-secret",
		LocalPath:    "/tmp/test.txt",
	}
	repo.Create(context.Background(), share)

	handler := webdav.NewHandler(repo, nil, logger)

	req := httptest.NewRequest(http.MethodGet, "/webdav/ocm/550e8400-e29b-41d4-a716-446655440000", nil)
	req.Header.Set("Authorization", "Bearer wrong-secret")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestShareNotFound(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	repo := shares.NewMemoryOutgoingShareRepo()
	handler := webdav.NewHandler(repo, nil, logger)

	req := httptest.NewRequest(http.MethodGet, "/webdav/ocm/550e8400-e29b-41d4-a716-446655440000", nil)
	req.Header.Set("Authorization", "Bearer some-secret")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestSuccessfulFileAccess(t *testing.T) {
	// Create a temp file
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.txt")
	content := []byte("hello world from webdav test")
	if err := os.WriteFile(tmpFile, content, 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	repo := shares.NewMemoryOutgoingShareRepo()

	// Create a share
	share := &shares.OutgoingShare{
		ProviderID:   "provider-123",
		WebDAVID:     "550e8400-e29b-41d4-a716-446655440000",
		SharedSecret: "correct-secret",
		LocalPath:    tmpFile,
	}
	repo.Create(context.Background(), share)

	handler := webdav.NewHandler(repo, nil, logger)

	// Test GET request
	req := httptest.NewRequest(http.MethodGet, "/webdav/ocm/550e8400-e29b-41d4-a716-446655440000/test.txt", nil)
	req.Header.Set("Authorization", "Bearer correct-secret")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body, _ := io.ReadAll(w.Body)
	if string(body) != string(content) {
		t.Errorf("content mismatch: got %q, want %q", string(body), string(content))
	}
}

func TestPROPFIND(t *testing.T) {
	// Create a temp file
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(tmpFile, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	repo := shares.NewMemoryOutgoingShareRepo()

	// Create a share
	share := &shares.OutgoingShare{
		ProviderID:   "provider-123",
		WebDAVID:     "550e8400-e29b-41d4-a716-446655440000",
		SharedSecret: "correct-secret",
		LocalPath:    tmpFile,
	}
	repo.Create(context.Background(), share)

	handler := webdav.NewHandler(repo, nil, logger)

	// Test PROPFIND request
	req := httptest.NewRequest("PROPFIND", "/webdav/ocm/550e8400-e29b-41d4-a716-446655440000", nil)
	req.Header.Set("Authorization", "Bearer correct-secret")
	req.Header.Set("Depth", "0")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// PROPFIND should return 207 Multi-Status
	if w.Code != http.StatusMultiStatus {
		t.Errorf("expected 207, got %d: %s", w.Code, w.Body.String())
	}
}

func TestExchangedTokenAuth(t *testing.T) {
	// Create a temp file
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.txt")
	content := []byte("hello from exchanged token test")
	if err := os.WriteFile(tmpFile, content, 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	repo := shares.NewMemoryOutgoingShareRepo()
	tokenStore := token.NewMemoryTokenStore()

	// Create a share
	share := &shares.OutgoingShare{
		ProviderID:   "provider-123",
		WebDAVID:     "550e8400-e29b-41d4-a716-446655440000",
		SharedSecret: "shared-secret",
		LocalPath:    tmpFile,
	}
	repo.Create(context.Background(), share)

	// Get the shareID (set by Create)
	createdShare, _ := repo.GetByWebDAVID(context.Background(), share.WebDAVID)

	// Store an exchanged token
	exchangedToken := "exchanged-access-token-12345"
	issuedToken := &token.IssuedToken{
		AccessToken: exchangedToken,
		ShareID:     createdShare.ShareID,
		ClientID:    "receiver.example.com",
		IssuedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	}
	tokenStore.Store(context.Background(), issuedToken)

	handler := webdav.NewHandler(repo, tokenStore, logger)

	t.Run("ExchangedTokenWorks", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/webdav/ocm/550e8400-e29b-41d4-a716-446655440000/test.txt", nil)
		req.Header.Set("Authorization", "Bearer "+exchangedToken)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
		}

		body, _ := io.ReadAll(w.Body)
		if string(body) != string(content) {
			t.Errorf("content mismatch: got %q, want %q", string(body), string(content))
		}
	})

	t.Run("WrongTokenRejected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/webdav/ocm/550e8400-e29b-41d4-a716-446655440000/test.txt", nil)
		req.Header.Set("Authorization", "Bearer wrong-token")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", w.Code)
		}
	})

	t.Run("SharedSecretStillWorks", func(t *testing.T) {
		// Even with token store present, shared secret should work
		req := httptest.NewRequest(http.MethodGet, "/webdav/ocm/550e8400-e29b-41d4-a716-446655440000/test.txt", nil)
		req.Header.Set("Authorization", "Bearer shared-secret")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("ExpiredTokenRejected", func(t *testing.T) {
		// Store an expired token
		expiredToken := "expired-token"
		expiredIssuedToken := &token.IssuedToken{
			AccessToken: expiredToken,
			ShareID:     createdShare.ShareID,
			ClientID:    "receiver.example.com",
			IssuedAt:    time.Now().Add(-2 * time.Hour),
			ExpiresAt:   time.Now().Add(-1 * time.Hour), // Expired an hour ago
		}
		tokenStore.Store(context.Background(), expiredIssuedToken)

		req := httptest.NewRequest(http.MethodGet, "/webdav/ocm/550e8400-e29b-41d4-a716-446655440000/test.txt", nil)
		req.Header.Set("Authorization", "Bearer "+expiredToken)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 for expired token, got %d", w.Code)
		}
	})

	t.Run("TokenForWrongShareRejected", func(t *testing.T) {
		// Store a token for a different share
		wrongShareToken := "wrong-share-token"
		wrongIssuedToken := &token.IssuedToken{
			AccessToken: wrongShareToken,
			ShareID:     "different-share-id", // Different share
			ClientID:    "receiver.example.com",
			IssuedAt:    time.Now(),
			ExpiresAt:   time.Now().Add(1 * time.Hour),
		}
		tokenStore.Store(context.Background(), wrongIssuedToken)

		req := httptest.NewRequest(http.MethodGet, "/webdav/ocm/550e8400-e29b-41d4-a716-446655440000/test.txt", nil)
		req.Header.Set("Authorization", "Bearer "+wrongShareToken)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 for token belonging to wrong share, got %d", w.Code)
		}
	})
}
