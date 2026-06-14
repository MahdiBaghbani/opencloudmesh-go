package ocmaux

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

func testLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestNew_FailsWithoutRequiredInputs(t *testing.T) {
	_, err := New(Inputs{}, map[string]any{}, testLog())
	if err == nil {
		t.Fatal("expected error when required inputs are missing")
	}
}

func TestNew_SucceedsWithInputs(t *testing.T) {
	svc, err := New(testOCMAuxInputs(), map[string]any{}, testLog())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if svc == nil {
		t.Fatal("expected non-nil service")
	}
}

func TestService_Prefix(t *testing.T) {
	svc, err := New(testOCMAuxInputs(), map[string]any{}, testLog())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if svc.Prefix() != "ocm-aux" {
		t.Errorf("expected prefix 'ocm-aux', got %q", svc.Prefix())
	}
}

func TestService_Handler(t *testing.T) {
	svc, err := New(testOCMAuxInputs(), map[string]any{}, testLog())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if svc.Handler() == nil {
		t.Error("expected non-nil Handler")
	}
}

func TestService_Close(t *testing.T) {
	svc, err := New(testOCMAuxInputs(), map[string]any{}, testLog())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := svc.Close(); err != nil {
		t.Errorf("unexpected error on Close: %v", err)
	}
}

func TestService_FederationsEndpoint(t *testing.T) {
	svc, err := New(testOCMAuxInputs(), map[string]any{}, testLog())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/federations", nil)
	w := httptest.NewRecorder()
	svc.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
	var result []json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Errorf("expected valid JSON array response: %v\nbody: %s", err, w.Body.String())
	}
	if len(result) != 0 {
		t.Errorf("expected empty array with nil TrustGroupMgr, got %d entries", len(result))
	}
}

func TestService_DiscoverEndpoint_MissingBase(t *testing.T) {
	svc, err := New(testOCMAuxInputs(), map[string]any{}, testLog())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/discover", nil)
	w := httptest.NewRecorder()
	svc.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Errorf("expected valid JSON response: %v", err)
	}
	if resp["success"] != false {
		t.Error("expected success=false in response")
	}
}

func TestService_DiscoverEndpoint_NoDiscoveryClient(t *testing.T) {
	in := testOCMAuxInputs()
	in.DiscoveryClient = nil
	svc, err := New(in, map[string]any{}, testLog())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/discover?base=https://example.com", nil)
	w := httptest.NewRecorder()
	svc.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusNotImplemented {
		t.Errorf("expected status 501, got %d", w.Code)
	}
}

func TestNew_WarnsOnUnusedConfigKeys(t *testing.T) {
	var logBuf testLogBuffer
	log := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	m := map[string]any{
		"unknown_key": "value",
	}
	_, err := New(testOCMAuxInputs(), m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !logBuf.contains("unused config keys") {
		t.Error("expected warning about unused config keys")
	}
}

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
