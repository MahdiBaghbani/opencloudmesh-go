package webdav

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token"
)

func testLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestNew_SucceedsWithInputs(t *testing.T) {
	m := map[string]any{}
	svc, err := New(testWebDAVInputs(), m, testLog())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if svc == nil {
		t.Fatal("expected non-nil service")
	}
}

func TestNew_UsesMinimalInputs(t *testing.T) {
	m := map[string]any{}
	svc, err := New(testWebDAVInputs(), m, testLog())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := svc.(*Service)
	if s.handler == nil {
		t.Fatal("expected non-nil handler")
	}
}

func TestService_StrictShareRejectsSharedSecret(t *testing.T) {
	repo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	strictShare := &sharesoutgoing.OutgoingShare{
		ProviderID:        "provider-strict-share",
		WebDAVID:          "11111111-1111-1111-1111-111111111111",
		SharedSecret:      "strict-share-secret",
		MustExchangeToken: true,
		ReceiverHost:      "receiver.example.com",
	}
	if err := repo.Create(nil, strictShare); err != nil {
		t.Fatalf("failed to seed outgoing share: %v", err)
	}

	in := Inputs{
		OutgoingShareRepo: repo,
		TokenStore:        token.NewMemoryTokenStore(),
	}
	svc, err := New(in, map[string]any{}, testLog())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	s := svc.(*Service)
	req := httptest.NewRequest(http.MethodGet, "/webdav/ocm/"+strictShare.WebDAVID, nil)
	req.Header.Set("Authorization", "Bearer "+strictShare.SharedSecret)
	w := httptest.NewRecorder()

	s.handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for strict share shared-secret access, got %d: %s", w.Code, w.Body.String())
	}
}

func TestService_Prefix(t *testing.T) {
	svc, err := New(testWebDAVInputs(), map[string]any{}, testLog())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if svc.Prefix() != "webdav" {
		t.Errorf("expected prefix 'webdav', got %q", svc.Prefix())
	}
}

func TestService_Unprotected(t *testing.T) {
	svc, err := New(testWebDAVInputs(), map[string]any{}, testLog())
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
	svc, err := New(testWebDAVInputs(), map[string]any{}, testLog())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if svc.Handler() == nil {
		t.Error("expected non-nil Handler")
	}
}

func TestService_Close(t *testing.T) {
	svc, err := New(testWebDAVInputs(), map[string]any{}, testLog())
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
	var logBuf testLogBuffer
	log := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	m := map[string]any{
		"unknown_key": "value",
	}

	_, err := New(testWebDAVInputs(), m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

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
