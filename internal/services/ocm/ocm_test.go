package ocm

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/deps"
)

// setupTestDeps creates minimal SharedDeps for the OCM service.
// SignatureMiddleware is nil (no-signature path), which is the simplest valid setup.
func setupTestDeps() {
	deps.ResetDeps()
	deps.SetDeps(&deps.Deps{
		Config: config.DevConfig(),
	})
}

func TestNew_FailsWithoutSharedDeps(t *testing.T) {
	deps.ResetDeps()

	m := map[string]any{}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	_, err := New(m, log)
	if err == nil {
		t.Error("expected error when SharedDeps not initialized")
	}
}

func TestNew_SucceedsWithSharedDeps(t *testing.T) {
	setupTestDeps()

	m := map[string]any{}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	svc, err := New(m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if svc == nil {
		t.Fatal("expected non-nil service")
	}
}

func TestService_Prefix(t *testing.T) {
	setupTestDeps()

	m := map[string]any{}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	svc, err := New(m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if svc.Prefix() != "ocm" {
		t.Errorf("expected prefix 'ocm', got %q", svc.Prefix())
	}
}

func TestService_Unprotected(t *testing.T) {
	setupTestDeps()

	m := map[string]any{}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	svc, err := New(m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	unprotected := svc.Unprotected()
	if len(unprotected) != 4 {
		t.Fatalf("expected 4 unprotected paths, got %d: %v", len(unprotected), unprotected)
	}

	expectedPaths := map[string]bool{
		"/shares":          false,
		"/notifications":   false,
		"/invite-accepted": false,
		"/token":           false,
	}
	for _, p := range unprotected {
		if _, ok := expectedPaths[p]; ok {
			expectedPaths[p] = true
		}
	}
	for p, found := range expectedPaths {
		if !found {
			t.Errorf("expected unprotected path %q not found", p)
		}
	}
}

func TestService_Handler(t *testing.T) {
	setupTestDeps()

	m := map[string]any{}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	svc, err := New(m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if svc.Handler() == nil {
		t.Error("expected non-nil Handler")
	}
}

func TestService_Close(t *testing.T) {
	setupTestDeps()

	m := map[string]any{}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	svc, err := New(m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := svc.Close(); err != nil {
		t.Errorf("unexpected error on Close: %v", err)
	}
}

// TestService_RoutingSmoke proves routes are wired by checking that GET on a
// POST-only endpoint returns 405 Method Not Allowed (chi behavior when the
// path exists but the method does not). This avoids triggering the handler
// with nil repos.
func TestService_RoutingSmoke(t *testing.T) {
	setupTestDeps()

	m := map[string]any{}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	svc, err := New(m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tests := []struct {
		name string
		path string
	}{
		{"shares", "/shares"},
		{"notifications", "/notifications"},
		{"invite-accepted", "/invite-accepted"},
		{"token", "/token"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			w := httptest.NewRecorder()
			svc.Handler().ServeHTTP(w, req)

			if w.Code != http.StatusMethodNotAllowed {
				t.Errorf("GET %s: expected status 405, got %d", tt.path, w.Code)
			}
		})
	}
}

func TestNew_WarnsOnUnusedConfigKeys(t *testing.T) {
	setupTestDeps()

	var logBuf testLogBuffer
	log := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	m := map[string]any{
		"unknown_key": "value",
	}

	_, err := New(m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !logBuf.contains("unused config keys") {
		t.Error("expected warning about unused config keys")
	}
}

// testLogBuffer is a simple buffer for capturing log output.
type testLogBuffer struct {
	data []byte
}

func (b *testLogBuffer) Write(p []byte) (n int, err error) {
	b.data = append(b.data, p...)
	return len(p), nil
}

func (b *testLogBuffer) contains(s string) bool {
	return len(b.data) > 0 && searchString(string(b.data), s)
}

func searchString(haystack, needle string) bool {
	for i := 0; i <= len(haystack)-len(needle); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
