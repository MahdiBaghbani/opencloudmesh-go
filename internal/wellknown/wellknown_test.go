package wellknown

import (
	"log/slog"
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
	if len(unprotected) != 2 {
		t.Errorf("expected 2 unprotected paths, got %d", len(unprotected))
	}

	// Check unprotected paths
	expectedPaths := map[string]bool{
		"/.well-known/ocm": false,
		"/ocm-provider":    false,
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
