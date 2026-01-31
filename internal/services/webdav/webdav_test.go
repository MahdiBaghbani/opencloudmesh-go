package webdav

import (
	"log/slog"
	"os"
	"testing"

	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/deps"
)

func TestNew_FailsWithoutSharedDeps(t *testing.T) {
	// Ensure deps are not set
	deps.ResetDeps()

	m := map[string]any{}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	_, err := New(m, log)
	if err == nil {
		t.Error("expected error when SharedDeps not initialized")
	}
}

func TestNew_SucceedsWithSharedDeps(t *testing.T) {
	deps.ResetDeps()
	deps.SetDeps(&deps.Deps{
		OutgoingShareRepo: sharesoutgoing.NewMemoryOutgoingShareRepo(),
		TokenStore:        token.NewMemoryTokenStore(),
	})

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

func TestNew_AcceptsConfigOptions(t *testing.T) {
	deps.ResetDeps()
	deps.SetDeps(&deps.Deps{
		OutgoingShareRepo: sharesoutgoing.NewMemoryOutgoingShareRepo(),
		TokenStore:        token.NewMemoryTokenStore(),
	})

	m := map[string]any{
		"webdav_token_exchange_mode": "lenient",
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	svc, err := New(m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if svc == nil {
		t.Fatal("expected non-nil service")
	}

	// Verify config was applied
	s := svc.(*Service)
	if s.conf.WebDAVTokenExchangeMode != "lenient" {
		t.Errorf("expected mode 'lenient', got %q", s.conf.WebDAVTokenExchangeMode)
	}
}

func TestNew_DefaultsToStrictMode(t *testing.T) {
	deps.ResetDeps()
	deps.SetDeps(&deps.Deps{
		OutgoingShareRepo: sharesoutgoing.NewMemoryOutgoingShareRepo(),
		TokenStore:        token.NewMemoryTokenStore(),
	})

	m := map[string]any{}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	svc, err := New(m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	s := svc.(*Service)
	if s.conf.WebDAVTokenExchangeMode != "strict" {
		t.Errorf("expected default mode 'strict', got %q", s.conf.WebDAVTokenExchangeMode)
	}
}

func TestService_Prefix(t *testing.T) {
	deps.ResetDeps()
	deps.SetDeps(&deps.Deps{
		OutgoingShareRepo: sharesoutgoing.NewMemoryOutgoingShareRepo(),
		TokenStore:        token.NewMemoryTokenStore(),
	})

	m := map[string]any{}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	svc, err := New(m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if svc.Prefix() != "webdav" {
		t.Errorf("expected prefix 'webdav', got %q", svc.Prefix())
	}
}

func TestService_Unprotected(t *testing.T) {
	deps.ResetDeps()
	deps.SetDeps(&deps.Deps{
		OutgoingShareRepo: sharesoutgoing.NewMemoryOutgoingShareRepo(),
		TokenStore:        token.NewMemoryTokenStore(),
	})

	m := map[string]any{}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	svc, err := New(m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	unprotected := svc.Unprotected()
	if len(unprotected) != 1 {
		t.Errorf("expected 1 unprotected path, got %d", len(unprotected))
	}

	if len(unprotected) > 0 && unprotected[0] != "/ocm" {
		t.Errorf("expected unprotected path '/ocm', got %q", unprotected[0])
	}
}

func TestService_Handler(t *testing.T) {
	deps.ResetDeps()
	deps.SetDeps(&deps.Deps{
		OutgoingShareRepo: sharesoutgoing.NewMemoryOutgoingShareRepo(),
		TokenStore:        token.NewMemoryTokenStore(),
	})

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
	deps.ResetDeps()
	deps.SetDeps(&deps.Deps{
		OutgoingShareRepo: sharesoutgoing.NewMemoryOutgoingShareRepo(),
		TokenStore:        token.NewMemoryTokenStore(),
	})

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

// Note: Endpoint-level tests for webdav behavior are in internal/webdav/webdav_test.go.
// The service-level tests here focus on the registry service interface (New, Prefix,
// Unprotected, Handler, Close) and config handling.
// Full end-to-end tests with proper path handling are in tests/integration/.

func TestNew_WarnsOnUnusedConfigKeys(t *testing.T) {
	deps.ResetDeps()
	deps.SetDeps(&deps.Deps{
		OutgoingShareRepo: sharesoutgoing.NewMemoryOutgoingShareRepo(),
		TokenStore:        token.NewMemoryTokenStore(),
	})

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

func TestConfig_ApplyDefaults(t *testing.T) {
	c := &Config{}
	c.ApplyDefaults()

	if c.WebDAVTokenExchangeMode != "strict" {
		t.Errorf("expected default mode 'strict', got %q", c.WebDAVTokenExchangeMode)
	}
}

func TestConfig_ApplyDefaults_PreservesExistingValue(t *testing.T) {
	c := &Config{WebDAVTokenExchangeMode: "lenient"}
	c.ApplyDefaults()

	if c.WebDAVTokenExchangeMode != "lenient" {
		t.Errorf("expected mode 'lenient' to be preserved, got %q", c.WebDAVTokenExchangeMode)
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
