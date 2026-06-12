package wellknown

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery/resolve"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
)

func TestNew_SucceedsWithResolveInputs(t *testing.T) {
	m := map[string]any{
		"ocmprovider": map[string]any{
			"endpoint": "https://example.com",
		},
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	svc, err := New(Inputs{Resolve: resolve.ResolveInputs{}}, m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if svc.Prefix() != "" {
		t.Errorf("expected empty prefix, got %q", svc.Prefix())
	}

	unprotected := svc.Unprotected()
	if len(unprotected) != 4 {
		t.Fatalf("expected 4 unprotected paths, got %d: %v", len(unprotected), unprotected)
	}
}

func TestNew_WarnsOnUnusedConfigKeys(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	m := map[string]any{
		"unknown_key": "value",
		"ocmprovider": map[string]any{
			"endpoint": "https://example.com",
		},
	}

	_, err := New(Inputs{Resolve: resolve.ResolveInputs{}}, m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNew_RejectsInvalidOCMProviderConfig(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	m := map[string]any{
		"ocmprovider": "not-a-map",
	}

	_, err := New(Inputs{Resolve: resolve.ResolveInputs{}}, m, log)
	if err == nil {
		t.Error("expected error for invalid ocmprovider config type")
	}
}

func TestService_HandlerReturnsValidResponse(t *testing.T) {
	m := map[string]any{
		"ocmprovider": map[string]any{
			"endpoint": "https://example.com",
		},
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	svc, err := New(Inputs{Resolve: resolve.ResolveInputs{}}, m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/.well-known/ocm", nil)
	w := httptest.NewRecorder()
	svc.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestService_Close(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	m := map[string]any{
		"ocmprovider": map[string]any{
			"endpoint": "https://example.com",
		},
	}

	svc, err := New(Inputs{Resolve: resolve.ResolveInputs{}}, m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := svc.Close(); err != nil {
		t.Errorf("unexpected error on Close: %v", err)
	}
}

func TestService_UnprotectedPaths(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	m := map[string]any{
		"ocmprovider": map[string]any{
			"endpoint": "https://example.com",
		},
	}

	svc, err := New(Inputs{Resolve: resolve.ResolveInputs{}}, m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := map[string]bool{
		"/.well-known/ocm":  false,
		"/.well-known/ocm/": false,
		"/ocm-provider":     false,
		"/ocm-provider/":    false,
	}
	for _, p := range svc.Unprotected() {
		if _, ok := expected[p]; ok {
			expected[p] = true
		}
	}
	for p, found := range expected {
		if !found {
			t.Errorf("expected unprotected path %q not found", p)
		}
	}
}

func TestService_TrailingSlashAliases(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	m := map[string]any{
		"ocmprovider": map[string]any{
			"endpoint": "https://example.com",
		},
	}

	svc, err := New(Inputs{Resolve: resolve.ResolveInputs{}}, m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, path := range []string{"/.well-known/ocm/", "/ocm-provider/"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		svc.Handler().ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("path %s: expected 200, got %d", path, w.Code)
		}
	}
}

func TestService_OCMProviderAlias(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	m := map[string]any{
		"ocmprovider": map[string]any{
			"endpoint": "https://example.com",
		},
	}

	svc, err := New(Inputs{Resolve: resolve.ResolveInputs{}}, m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/ocm-provider", nil)
	w := httptest.NewRecorder()
	svc.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestService_PercentEncodedPath(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	m := map[string]any{
		"ocmprovider": map[string]any{
			"endpoint": "https://example.com",
		},
	}

	svc, err := New(Inputs{Resolve: resolve.ResolveInputs{}}, m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/.well-known/ocm", nil)
	req.URL.RawPath = "/.well-known%2Focm"
	w := httptest.NewRecorder()
	svc.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for percent-encoded path, got %d", w.Code)
	}
}

func TestService_APIVersionOverride(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
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

	svc, err := New(Inputs{Resolve: resolve.ResolveInputs{}}, m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/.well-known/ocm", nil)
	req.Header.Set("User-Agent", "Nextcloud Server Crawler/1.0")
	w := httptest.NewRecorder()
	svc.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var disc spec.Discovery
	if err := json.Unmarshal(w.Body.Bytes(), &disc); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if disc.APIVersion != "1.1" {
		t.Fatalf("expected apiVersion 1.1 for crawler override, got %q", disc.APIVersion)
	}
}

func TestService_APIVersionOverride_NoMatchUsesDefault(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
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

	svc, err := New(Inputs{Resolve: resolve.ResolveInputs{}}, m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/.well-known/ocm", nil)
	req.Header.Set("User-Agent", "SomeOtherClient/1.0")
	w := httptest.NewRecorder()
	svc.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var disc spec.Discovery
	if err := json.Unmarshal(w.Body.Bytes(), &disc); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if disc.APIVersion != "1.2.2" {
		t.Fatalf("expected default apiVersion 1.2.2, got %q", disc.APIVersion)
	}
}

func TestService_APIVersionOverride_NoOverridesUsesDefault(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	m := map[string]any{
		"ocmprovider": map[string]any{
			"endpoint": "https://example.com",
		},
	}

	svc, err := New(Inputs{Resolve: resolve.ResolveInputs{}}, m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/.well-known/ocm", nil)
	w := httptest.NewRecorder()
	svc.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var disc spec.Discovery
	if err := json.Unmarshal(w.Body.Bytes(), &disc); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if disc.APIVersion != "1.2.2" {
		t.Fatalf("expected default apiVersion 1.2.2, got %q", disc.APIVersion)
	}
}
