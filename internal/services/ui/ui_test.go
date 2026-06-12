package ui

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func testLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestNew_SucceedsWithInputs(t *testing.T) {
	svc, err := New(Inputs{}, map[string]any{}, testLog())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if svc == nil {
		t.Fatal("expected non-nil service")
	}
}

func TestNew_AcceptsExternalBasePath(t *testing.T) {
	svc, err := New(Inputs{ExternalBasePath: "/ocm"}, map[string]any{}, testLog())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if svc == nil {
		t.Fatal("expected non-nil service")
	}
}

func TestService_Prefix(t *testing.T) {
	svc, err := New(Inputs{}, map[string]any{}, testLog())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if svc.Prefix() != "ui" {
		t.Errorf("expected prefix 'ui', got %q", svc.Prefix())
	}
}

func TestService_Unprotected(t *testing.T) {
	svc, err := New(Inputs{}, map[string]any{}, testLog())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	unprotected := svc.Unprotected()
	if len(unprotected) != 1 {
		t.Errorf("expected 1 unprotected path, got %d", len(unprotected))
	}
	if len(unprotected) > 0 && unprotected[0] != "/login" {
		t.Errorf("expected unprotected path '/login', got %q", unprotected[0])
	}
}

func TestService_Unprotected_WayfEnabled(t *testing.T) {
	m := map[string]any{
		"wayf": map[string]any{"enabled": true},
	}
	svc, err := New(Inputs{}, m, testLog())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	unprotected := svc.Unprotected()
	expected := map[string]bool{"/login": false, "/wayf": false}
	for _, p := range unprotected {
		if _, ok := expected[p]; !ok {
			t.Errorf("unexpected unprotected path %q", p)
		}
		expected[p] = true
	}
	for p, found := range expected {
		if !found {
			t.Errorf("expected unprotected path %q not found", p)
		}
	}
}

func TestService_Handler(t *testing.T) {
	svc, err := New(Inputs{}, map[string]any{}, testLog())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if svc.Handler() == nil {
		t.Error("expected non-nil Handler")
	}
}

func TestService_Close(t *testing.T) {
	svc, err := New(Inputs{}, map[string]any{}, testLog())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := svc.Close(); err != nil {
		t.Errorf("unexpected error on Close: %v", err)
	}
}

func TestService_LoginEndpoint(t *testing.T) {
	svc, err := New(Inputs{}, map[string]any{}, testLog())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	w := httptest.NewRecorder()
	svc.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
	contentType := w.Header().Get("Content-Type")
	if !strings.HasPrefix(contentType, "text/html") {
		t.Errorf("expected Content-Type text/html, got %q", contentType)
	}
	body := w.Body.String()
	if !strings.Contains(body, "<html") && !strings.Contains(body, "<!DOCTYPE") && !strings.Contains(body, "<form") {
		t.Error("expected HTML content in response body")
	}
}

func TestService_InboxEndpoint(t *testing.T) {
	svc, err := New(Inputs{}, map[string]any{}, testLog())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/inbox", nil)
	w := httptest.NewRecorder()
	svc.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
	contentType := w.Header().Get("Content-Type")
	if !strings.HasPrefix(contentType, "text/html") {
		t.Errorf("expected Content-Type text/html, got %q", contentType)
	}
	body := w.Body.String()
	if !strings.Contains(body, "<html") && !strings.Contains(body, "<!DOCTYPE") && !strings.Contains(body, "inbox") {
		t.Error("expected HTML content in response body")
	}
}

func TestService_LoginEndpoint_WithBasePath(t *testing.T) {
	svc, err := New(Inputs{ExternalBasePath: "/ocm"}, map[string]any{}, testLog())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	w := httptest.NewRecorder()
	svc.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "/ocm") {
		t.Error("expected base path '/ocm' in response body")
	}
}

func TestService_WayfEndpoint_Disabled(t *testing.T) {
	svc, err := New(Inputs{}, map[string]any{}, testLog())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/wayf", nil)
	w := httptest.NewRecorder()
	svc.Handler().ServeHTTP(w, req)
	if w.Code == http.StatusOK {
		t.Error("expected non-200 when WAYF is disabled")
	}
}

func TestService_WayfEndpoint_Enabled(t *testing.T) {
	m := map[string]any{
		"wayf": map[string]any{"enabled": true},
	}
	svc, err := New(Inputs{}, m, testLog())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/wayf?token=abc123", nil)
	w := httptest.NewRecorder()
	svc.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/html") {
		t.Errorf("expected text/html content type, got %q", ct)
	}
	body := w.Body.String()
	if !strings.Contains(body, "wayf") && !strings.Contains(body, "WAYF") && !strings.Contains(body, "provider") {
		t.Error("expected WAYF-related content in response")
	}
}

func TestService_AcceptInvite_RendersWithoutSession(t *testing.T) {
	m := map[string]any{
		"wayf": map[string]any{"enabled": true},
	}
	svc, err := New(Inputs{ExternalBasePath: "/ocm"}, m, testLog())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/accept-invite?token=abc&providerDomain=remote.example.com", nil)
	w := httptest.NewRecorder()
	svc.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/html") {
		t.Errorf("expected text/html, got %q", ct)
	}
}

func TestService_AcceptInvite_RendersWithSession(t *testing.T) {
	m := map[string]any{
		"wayf": map[string]any{"enabled": true},
	}
	svc, err := New(Inputs{}, m, testLog())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/accept-invite?token=abc&providerDomain=remote.example.com", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: "valid-token"})
	w := httptest.NewRecorder()
	svc.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/html") {
		t.Errorf("expected text/html, got %q", ct)
	}
}

func TestNew_WarnsOnUnusedConfigKeys(t *testing.T) {
	var logBuf testLogBuffer
	log := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	m := map[string]any{
		"unknown_key": "value",
	}
	_, err := New(Inputs{}, m, log)
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
	return strings.Contains(string(b.data), s)
}
