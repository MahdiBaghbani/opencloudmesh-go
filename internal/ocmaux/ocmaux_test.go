package ocmaux

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/services"
)

func TestNew_FailsWithoutSharedDeps(t *testing.T) {
	// Ensure deps are not set
	services.ResetDeps()

	m := map[string]any{}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	_, err := New(m, log)
	if err == nil {
		t.Error("expected error when SharedDeps not initialized")
	}
}

func TestNew_SucceedsWithSharedDeps(t *testing.T) {
	services.ResetDeps()
	services.SetDeps(&services.Deps{})

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
	services.ResetDeps()
	services.SetDeps(&services.Deps{})

	m := map[string]any{}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	svc, err := New(m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if svc.Prefix() != "ocm-aux" {
		t.Errorf("expected prefix 'ocm-aux', got %q", svc.Prefix())
	}
}

func TestService_Unprotected(t *testing.T) {
	services.ResetDeps()
	services.SetDeps(&services.Deps{})

	m := map[string]any{}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	svc, err := New(m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	unprotected := svc.Unprotected()
	if len(unprotected) != 2 {
		t.Errorf("expected 2 unprotected paths, got %d", len(unprotected))
	}

	expectedPaths := map[string]bool{
		"/federations": false,
		"/discover":    false,
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
	services.ResetDeps()
	services.SetDeps(&services.Deps{})

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
	services.ResetDeps()
	services.SetDeps(&services.Deps{})

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

func TestService_FederationsEndpoint(t *testing.T) {
	services.ResetDeps()
	services.SetDeps(&services.Deps{
		// FederationMgr is nil - handler should still work
	})

	m := map[string]any{}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	svc, err := New(m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/federations", nil)
	w := httptest.NewRecorder()

	svc.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	// Should return valid JSON with empty federations
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Errorf("expected valid JSON response: %v", err)
	}

	if _, ok := resp["federations"]; !ok {
		t.Error("expected 'federations' key in response")
	}
}

func TestService_DiscoverEndpoint_MissingBase(t *testing.T) {
	services.ResetDeps()
	services.SetDeps(&services.Deps{})

	m := map[string]any{}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	svc, err := New(m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/discover", nil)
	w := httptest.NewRecorder()

	svc.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}

	// Should return JSON error
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Errorf("expected valid JSON response: %v", err)
	}

	if resp["success"] != false {
		t.Error("expected success=false in response")
	}
}

func TestService_DiscoverEndpoint_NoDiscoveryClient(t *testing.T) {
	services.ResetDeps()
	services.SetDeps(&services.Deps{
		// DiscoveryClient is nil
	})

	m := map[string]any{}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	svc, err := New(m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/discover?base=https://example.com", nil)
	w := httptest.NewRecorder()

	svc.Handler().ServeHTTP(w, req)

	// Should return 501 Not Implemented when discovery client is nil
	if w.Code != http.StatusNotImplemented {
		t.Errorf("expected status 501, got %d", w.Code)
	}
}

func TestNew_WarnsOnUnusedConfigKeys(t *testing.T) {
	services.ResetDeps()
	services.SetDeps(&services.Deps{})

	// Create a logger that captures output
	var logBuf testLogBuffer
	log := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	m := map[string]any{
		"unknown_key": "value",
	}

	_, err := New(m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check that a warning was logged
	if !logBuf.contains("unused config keys") {
		t.Error("expected warning about unused config keys")
	}
}

// testLogBuffer is a simple buffer for capturing log output
type testLogBuffer struct {
	data []byte
}

func (b *testLogBuffer) Write(p []byte) (n int, err error) {
	b.data = append(b.data, p...)
	return len(p), nil
}

func (b *testLogBuffer) contains(s string) bool {
	return len(b.data) > 0 && string(b.data) != "" && 
		(len(s) == 0 || (len(b.data) >= len(s) && containsString(string(b.data), s)))
}

func containsString(haystack, needle string) bool {
	return len(haystack) >= len(needle) && 
		(haystack == needle || 
		 (len(haystack) > len(needle) && searchString(haystack, needle)))
}

func searchString(haystack, needle string) bool {
	for i := 0; i <= len(haystack)-len(needle); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
