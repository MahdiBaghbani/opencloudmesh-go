// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package webdav

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tsrepos "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/repos"

	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token"
)

func testLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestNew_SucceedsWithInputs(t *testing.T) {
	m := map[string]any{}

	svc, err := New(testWebDAVInputs(t), m, testLog())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if svc == nil {
		t.Fatal("expected non-nil service")
	}
}

func TestNew_UsesMinimalInputs(t *testing.T) {
	m := map[string]any{}

	svc, err := New(testWebDAVInputs(t), m, testLog())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	s, ok := svc.(*Service)
	if !ok {
		t.Fatal("expected s type *Service")
	}

	if s.handler == nil {
		t.Fatal("expected non-nil handler")
	}
}

func TestService_StrictShareRejectsSharedSecret(t *testing.T) {
	repo := tsrepos.OpenMemory(t).OutgoingShares

	strictShare := &sharesoutgoing.OutgoingShare{
		ProviderID:   "provider-strict-share",
		WebDAVID:     "11111111-1111-1111-1111-111111111111",
		SharedSecret: "strict-share-secret",
		ReceiverHost: "receiver.example.com",
		Requirements: []string{spec.RequirementMustExchangeToken},
	}
	if err := repo.Create(context.TODO(), strictShare); err != nil {
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

	s, ok := svc.(*Service)
	if !ok {
		t.Fatal("expected s type *Service")
	}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/webdav/ocm/"+strictShare.WebDAVID, nil)
	req.Header.Set("Authorization", "Bearer "+strictShare.SharedSecret)

	w := httptest.NewRecorder()

	s.handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for strict share shared-secret access, got %d: %s", w.Code, w.Body.String())
	}
}

// TestService_NonStrictShareAcceptsSharedSecret covers the non-strict legacy sender
// fork at the service layer: a non-strict share (Requirements omit
// must-exchange-token) authenticates with a sharedSecret Bearer and succeeds.
func TestService_NonStrictShareAcceptsSharedSecret(t *testing.T) {
	dir := t.TempDir()

	filePath := filepath.Join(dir, "hello.txt")
	if err := os.WriteFile(filePath, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}

	repo := tsrepos.OpenMemory(t).OutgoingShares

	share := &sharesoutgoing.OutgoingShare{
		ProviderID:   "provider-non-strict",
		WebDAVID:     "11111111-1111-1111-1111-111111111111",
		SharedSecret: "non-strict-secret",
		LocalPath:    filePath,
		ReceiverHost: "receiver.example.com",
	}
	if err := repo.Create(context.TODO(), share); err != nil {
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

	s, ok := svc.(*Service)
	if !ok {
		t.Fatal("expected s type *Service")
	}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/webdav/ocm/"+share.WebDAVID+"/hello.txt", nil)
	req.Header.Set("Authorization", "Bearer "+share.SharedSecret)

	w := httptest.NewRecorder()

	s.handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for non-strict shared-secret access, got %d: %s", w.Code, w.Body.String())
	}
}

func TestService_Prefix(t *testing.T) {
	svc, err := New(testWebDAVInputs(t), map[string]any{}, testLog())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if svc.Prefix() != "webdav" {
		t.Errorf("expected prefix 'webdav', got %q", svc.Prefix())
	}
}

func TestService_Handler(t *testing.T) {
	svc, err := New(testWebDAVInputs(t), map[string]any{}, testLog())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if svc.Handler() == nil {
		t.Error("expected non-nil Handler")
	}
}

func TestService_Close(t *testing.T) {
	svc, err := New(testWebDAVInputs(t), map[string]any{}, testLog())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := svc.Close(); err != nil {
		t.Errorf("unexpected error on Close: %v", err)
	}
}

// Note: Endpoint-level tests for webdav behavior are in internal/webdav/webdav_test.go.
// The service-level tests here focus on the registry service interface (New, Prefix,
// Handler, Close) and config handling.

func TestNew_WarnsOnUnusedConfigKeys(t *testing.T) {
	var logBuf testLogBuffer

	log := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	m := map[string]any{
		"unknown_key": "value",
	}

	_, err := New(testWebDAVInputs(t), m, log)
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
		(len(s) == 0 || (len(b.data) >= len(s) && strings.Contains(string(b.data), s)))
}
