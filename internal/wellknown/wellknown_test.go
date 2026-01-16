package wellknown

import (
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

	m := map[string]any{
		"ocmprovider": map[string]any{
			"endpoint": "https://example.com",
		},
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	_, err := New(m, log)
	if err == nil {
		t.Error("expected error when SharedDeps not initialized")
	}
}

func TestNew_SucceedsWithSharedDeps(t *testing.T) {
	services.ResetDeps()
	services.SetDeps(&services.Deps{})

	m := map[string]any{
		"ocmprovider": map[string]any{
			"endpoint": "https://example.com",
		},
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	svc, err := New(m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if svc.Prefix() != "" {
		t.Errorf("expected empty prefix, got %q", svc.Prefix())
	}

	unprotected := svc.Unprotected()
	if len(unprotected) != 4 {
		t.Errorf("expected 4 unprotected paths, got %d", len(unprotected))
	}

	// Check unprotected paths (including trailing-slash aliases)
	expectedPaths := map[string]bool{
		"/.well-known/ocm":  false,
		"/.well-known/ocm/": false,
		"/ocm-provider":     false,
		"/ocm-provider/":    false,
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

	if svc.Handler() == nil {
		t.Error("expected non-nil Handler")
	}

	// Close should not error
	if err := svc.Close(); err != nil {
		t.Errorf("unexpected error on Close: %v", err)
	}
}

func TestNew_ConfigDecodeError(t *testing.T) {
	services.ResetDeps()
	services.SetDeps(&services.Deps{})

	// Pass invalid config structure
	m := map[string]any{
		"ocmprovider": "not-a-map", // should be a map
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	_, err := New(m, log)
	if err == nil {
		t.Error("expected error for invalid config structure")
	}
}

func TestConfig_ApplyDefaults(t *testing.T) {
	c := &Config{}
	c.ApplyDefaults()

	// Should apply defaults to nested OCMProvider
	if c.OCMProvider.OCMPrefix != "ocm" {
		t.Errorf("expected OCMProvider.OCMPrefix 'ocm', got %q", c.OCMProvider.OCMPrefix)
	}
}

func TestHandler_ClearsRawPath(t *testing.T) {
	// Smoke test: verify Handler() wraps with RawPath clearing
	services.ResetDeps()
	services.SetDeps(&services.Deps{})

	m := map[string]any{
		"ocmprovider": map[string]any{
			"endpoint": "https://example.com",
		},
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	svc, err := New(m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	handler := svc.Handler()

	// Create request with RawPath set (simulating percent-encoded segments)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/ocm", nil)
	req.URL.RawPath = "/.well-known/ocm"

	// Verify RawPath is set before calling handler
	if req.URL.RawPath == "" {
		t.Fatal("test setup error: RawPath should be set")
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// The handler should have cleared RawPath before routing.
	// We can't directly observe this from outside, but we verify the request
	// was processed (status 200) which means chi routing worked correctly
	// even with RawPath initially set.
	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d (RawPath clearing may have failed)", rec.Code)
	}
}

func TestTrailingSlashAliases_ReturnSameResponse(t *testing.T) {
	services.ResetDeps()
	services.SetDeps(&services.Deps{})

	m := map[string]any{
		"ocmprovider": map[string]any{
			"endpoint": "https://example.com",
		},
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	svc, err := New(m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	handler := svc.Handler()

	testCases := []struct {
		name     string
		path     string
		aliasOf  string
	}{
		{"well-known trailing slash", "/.well-known/ocm/", "/.well-known/ocm"},
		{"ocm-provider trailing slash", "/ocm-provider/", "/ocm-provider"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Get response from primary path
			req1 := httptest.NewRequest(http.MethodGet, tc.aliasOf, nil)
			rec1 := httptest.NewRecorder()
			handler.ServeHTTP(rec1, req1)

			// Get response from trailing-slash alias
			req2 := httptest.NewRequest(http.MethodGet, tc.path, nil)
			rec2 := httptest.NewRecorder()
			handler.ServeHTTP(rec2, req2)

			if rec1.Code != http.StatusOK {
				t.Errorf("primary path %s: expected status 200, got %d", tc.aliasOf, rec1.Code)
			}
			if rec2.Code != http.StatusOK {
				t.Errorf("alias path %s: expected status 200, got %d", tc.path, rec2.Code)
			}
			if rec1.Body.String() != rec2.Body.String() {
				t.Errorf("responses differ:\n  primary: %s\n  alias: %s", rec1.Body.String(), rec2.Body.String())
			}
		})
	}
}

func TestAPIVersionOverride_MatchingUserAgent(t *testing.T) {
	services.ResetDeps()
	services.SetDeps(&services.Deps{})

	m := map[string]any{
		"ocmprovider": map[string]any{
			"endpoint": "https://example.com",
			"api_version_overrides": []map[string]any{
				{
					"user_agent_contains": "Nextcloud Server Crawler",
					"api_version":         "1.1",
				},
			},
		},
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	svc, err := New(m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	handler := svc.Handler()

	// Request with matching User-Agent
	req := httptest.NewRequest(http.MethodGet, "/.well-known/ocm", nil)
	req.Header.Set("User-Agent", "Nextcloud Server Crawler/30.0.0")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	body := rec.Body.String()
	// Check that apiVersion is 1.1 (the override), not the default 1.2.2
	if !contains(body, `"apiVersion":"1.1"`) {
		t.Errorf("expected apiVersion 1.1 in response, got: %s", body)
	}
}

func TestAPIVersionOverride_NoMatch_UsesDefault(t *testing.T) {
	services.ResetDeps()
	services.SetDeps(&services.Deps{})

	m := map[string]any{
		"ocmprovider": map[string]any{
			"endpoint": "https://example.com",
			"api_version_overrides": []map[string]any{
				{
					"user_agent_contains": "Nextcloud Server Crawler",
					"api_version":         "1.1",
				},
			},
		},
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	svc, err := New(m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	handler := svc.Handler()

	// Request with non-matching User-Agent
	req := httptest.NewRequest(http.MethodGet, "/.well-known/ocm", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; SomeBot/1.0)")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	body := rec.Body.String()
	// Check that apiVersion is the default 1.2.2
	if !contains(body, `"apiVersion":"1.2.2"`) {
		t.Errorf("expected default apiVersion 1.2.2 in response, got: %s", body)
	}
}

func TestAPIVersionOverride_NoOverrides_UsesDefault(t *testing.T) {
	services.ResetDeps()
	services.SetDeps(&services.Deps{})

	m := map[string]any{
		"ocmprovider": map[string]any{
			"endpoint": "https://example.com",
			// No api_version_overrides
		},
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	svc, err := New(m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	handler := svc.Handler()

	req := httptest.NewRequest(http.MethodGet, "/.well-known/ocm", nil)
	req.Header.Set("User-Agent", "Nextcloud Server Crawler/30.0.0")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	body := rec.Body.String()
	// Without overrides configured, should use default 1.2.2
	if !contains(body, `"apiVersion":"1.2.2"`) {
		t.Errorf("expected default apiVersion 1.2.2 in response, got: %s", body)
	}
}

// contains checks if substr is in s (simple helper for tests)
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsAt(s, substr))
}

func containsAt(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
