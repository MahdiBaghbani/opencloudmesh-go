// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package ui

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/localidentity"
	tslocalid "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/localidentity"
)

func testLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestNew_SucceedsWithInputs(t *testing.T) {
	t.Parallel()

	svc, err := New(Inputs{}, map[string]any{}, testLog())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if svc == nil {
		t.Fatal("expected non-nil service")
	}
}

func testIdentity(t *testing.T, basePath string) localidentity.Identity {
	t.Helper()

	return tslocalid.MustTestIdentity(t, "https://localhost:9200", basePath)
}

func TestNew_AcceptsExternalBasePath(t *testing.T) {
	t.Parallel()

	svc, err := New(Inputs{LocalIdentity: testIdentity(t, "/ocm")}, map[string]any{}, testLog())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if svc == nil {
		t.Fatal("expected non-nil service")
	}
}

func TestService_Prefix(t *testing.T) {
	t.Parallel()

	svc, err := New(Inputs{}, map[string]any{}, testLog())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if svc.Prefix() != "ui" {
		t.Errorf("expected prefix 'ui', got %q", svc.Prefix())
	}
}

func TestService_Handler(t *testing.T) {
	t.Parallel()

	svc, err := New(Inputs{}, map[string]any{}, testLog())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if svc.Handler() == nil {
		t.Error("expected non-nil Handler")
	}
}

func TestService_Close(t *testing.T) {
	t.Parallel()

	svc, err := New(Inputs{}, map[string]any{}, testLog())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := svc.Close(); err != nil {
		t.Errorf("unexpected error on Close: %v", err)
	}
}

// assertEndpointServesHTML GETs path and asserts a 200 text/html response
// whose body contains HTML or the endpoint-specific marker.
func assertEndpointServesHTML(t *testing.T, path, marker string) {
	t.Helper()

	svc, err := New(Inputs{}, map[string]any{}, testLog())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil)
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
	if !strings.Contains(body, "<html") && !strings.Contains(body, "<!DOCTYPE") && !strings.Contains(body, marker) {
		t.Error("expected HTML content in response body")
	}
}

func TestService_LoginEndpoint(t *testing.T) {
	t.Parallel()
	assertEndpointServesHTML(t, "/login", "<form")
}

func TestService_InboxEndpoint(t *testing.T) {
	t.Parallel()
	assertEndpointServesHTML(t, "/inbox", "inbox")
}

func TestService_LoginEndpoint_WithBasePath(t *testing.T) {
	t.Parallel()

	svc, err := New(Inputs{LocalIdentity: testIdentity(t, "/ocm")}, map[string]any{}, testLog())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/login", nil)
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
	t.Parallel()

	svc, err := New(Inputs{}, map[string]any{}, testLog())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/wayf", nil)
	w := httptest.NewRecorder()
	svc.Handler().ServeHTTP(w, req)

	if w.Code == http.StatusOK {
		t.Error("expected non-200 when WAYF is disabled")
	}
}

func TestService_WayfEndpoint_Enabled(t *testing.T) {
	t.Parallel()

	m := map[string]any{
		"wayf": map[string]any{"enabled": true},
	}

	svc, err := New(Inputs{}, m, testLog())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/wayf?token=abc123", nil)
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

func TestService_AcceptInvite_RendersTemplate(t *testing.T) {
	t.Parallel()

	m := map[string]any{
		"invite_accept": map[string]any{"enabled": true},
	}

	svc, err := New(Inputs{LocalIdentity: testIdentity(t, "/ocm")}, m, testLog())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/accept-invite?token=abc&providerDomain=remote.example.com", nil)
	w := httptest.NewRecorder()
	svc.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	ct := w.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/html") {
		t.Errorf("expected text/html, got %q", ct)
	}

	body := w.Body.String()
	if !strings.Contains(body, "abc") || !strings.Contains(body, "remote.example.com") {
		t.Error("expected accept-invite template to render query token and provider domain")
	}
}

func TestNew_WarnsOnUnusedConfigKeys(t *testing.T) {
	t.Parallel()

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
