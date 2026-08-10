// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package webdav

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token"
)

func TestValidateCredential_ExchangedTokenSucceeds(t *testing.T) {
	t.Parallel()

	repo := newMockOutgoingShareRepo()
	tokenStore := newMockTokenStore()
	share := seedShare(t, repo)

	ctx := context.Background()
	if err := tokenStore.Store(ctx, unexpiredTestToken("exchanged-token-123", share.ShareID)); err != nil {
		t.Fatal(err)
	}

	handler := NewHandler(repo, tokenStore, nil)

	authorized := handler.validateCredential(ctx, share, "exchanged-token-123")
	if !authorized {
		t.Error("expected authorization to succeed with valid exchanged token")
	}
}

func TestValidateCredential_AcceptsSharedSecretForNonStrict(t *testing.T) {
	t.Parallel()

	repo := newMockOutgoingShareRepo()
	tokenStore := newMockTokenStore()
	share := seedShare(t, repo)

	handler := NewHandler(repo, tokenStore, nil)

	authorized := handler.validateCredential(context.Background(), share, share.SharedSecret)
	if !authorized {
		t.Error("expected shared-secret authorization to succeed for non-strict share")
	}
}

func TestValidateCredential_RejectsSharedSecretForStrict(t *testing.T) {
	t.Parallel()

	repo := newMockOutgoingShareRepo()
	tokenStore := newMockTokenStore()
	share := seedShareWithRequirements(t, repo, "share-1", []string{spec.RequirementMustExchangeToken})

	handler := NewHandler(repo, tokenStore, nil)

	authorized := handler.validateCredential(context.Background(), share, share.SharedSecret)
	if authorized {
		t.Error("expected shared-secret authorization to fail for strict share")
	}
}

func TestValidateCredential_RejectsWrongShareBinding(t *testing.T) {
	t.Parallel()

	repo := newMockOutgoingShareRepo()
	tokenStore := newMockTokenStore()
	share := seedShare(t, repo)

	ctx := context.Background()
	if err := tokenStore.Store(ctx, unexpiredTestToken("bound-to-other-share", "other-share")); err != nil {
		t.Fatal(err)
	}

	handler := NewHandler(repo, tokenStore, nil)

	authorized := handler.validateCredential(ctx, share, "bound-to-other-share")
	if authorized {
		t.Error("expected authorization to fail for wrong share binding")
	}
}

func TestValidateCredential_RejectsNearMissSecret(t *testing.T) {
	t.Parallel()

	repo := newMockOutgoingShareRepo()
	share := seedShare(t, repo)

	handler := NewHandler(repo, newMockTokenStore(), nil)

	authorized := handler.validateCredential(context.Background(), share, "secret124")
	if authorized {
		t.Error("expected equal-length near-miss shared secret to be rejected")
	}
}

func TestValidateCredential_RejectsUnknownToken(t *testing.T) {
	t.Parallel()

	repo := newMockOutgoingShareRepo()
	tokenStore := newMockTokenStore()
	share := seedShare(t, repo)

	handler := NewHandler(repo, tokenStore, nil)

	authorized := handler.validateCredential(context.Background(), share, "unknown-token")
	if authorized {
		t.Error("expected authorization to fail for unknown token")
	}
}

func TestExtractCredential_BearerOnly(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/webdav/ocm/"+testWebDAVID, nil)
	req.Header.Set("Authorization", "Bearer my-token")

	cred := extractCredential(req)
	if cred == nil || cred.Token != "my-token" {
		t.Fatalf("expected Bearer token, got %+v", cred)
	}
}

func TestExtractCredential_RejectsBasic(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/webdav/ocm/"+testWebDAVID, nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")

	if extractCredential(req) != nil {
		t.Error("expected nil for Basic auth")
	}
}

func TestExtractCredential_RejectsDigest(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/webdav/ocm/"+testWebDAVID, nil)
	req.Header.Set("Authorization", "Digest username=alice")

	if extractCredential(req) != nil {
		t.Error("expected nil for Digest auth")
	}
}

func assertBearerWWWAuthenticate(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()

	challenge := w.Header().Get("WWW-Authenticate")
	if challenge != `Bearer realm="OCM WebDAV"` {
		t.Errorf("WWW-Authenticate = %q, want Bearer-only challenge", challenge)
	}

	if strings.Contains(challenge, "Basic") {
		t.Errorf("WWW-Authenticate must not advertise Basic, got %q", challenge)
	}
}

func TestServeHTTP_MissingAuthBearerOnlyChallenge(t *testing.T) {
	t.Parallel()

	repo := newMockOutgoingShareRepo()
	_ = seedShare(t, repo)
	handler := NewHandler(repo, newMockTokenStore(), nil)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/webdav/ocm/"+testWebDAVID, nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}

	assertBearerWWWAuthenticate(t, w)
}

func TestServeHTTP_BearerWithValidExchangedTokenSucceeds(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	filePath := filepath.Join(dir, "hello.txt")
	if err := os.WriteFile(filePath, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}

	repo := newMockOutgoingShareRepo()
	share := seedShare(t, repo)

	share.LocalPath = filePath
	if err := repo.Update(context.Background(), share); err != nil {
		t.Fatal(err)
	}

	tokenStore := newMockTokenStore()
	if err := tokenStore.Store(context.Background(), unexpiredTestToken("valid-token", share.ShareID)); err != nil {
		t.Fatal(err)
	}

	handler := NewHandler(repo, tokenStore, nil)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/webdav/ocm/"+testWebDAVID+"/hello.txt", nil)
	req.Header.Set("Authorization", "Bearer valid-token")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestServeHTTP_BearerServesFileAtResourceRoot(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	filePath := filepath.Join(dir, "hello.txt")
	if err := os.WriteFile(filePath, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}

	repo := newMockOutgoingShareRepo()
	share := seedShare(t, repo)

	share.LocalPath = filePath
	if err := repo.Update(context.Background(), share); err != nil {
		t.Fatal(err)
	}

	tokenStore := newMockTokenStore()
	if err := tokenStore.Store(context.Background(), unexpiredTestToken("valid-token", share.ShareID)); err != nil {
		t.Fatal(err)
	}

	handler := NewHandler(repo, tokenStore, nil)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/webdav/ocm/"+testWebDAVID, nil)
	req.Header.Set("Authorization", "Bearer valid-token")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	if w.Body.String() != "hello" {
		t.Errorf("expected body %q, got %q", "hello", w.Body.String())
	}
}

func TestServeHTTP_BearerServesFileForNonBasenameRequest(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	filePath := filepath.Join(dir, "hello.txt")
	if err := os.WriteFile(filePath, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}

	repo := newMockOutgoingShareRepo()
	share := seedShare(t, repo)

	share.LocalPath = filePath
	if err := repo.Update(context.Background(), share); err != nil {
		t.Fatal(err)
	}

	tokenStore := newMockTokenStore()
	if err := tokenStore.Store(context.Background(), unexpiredTestToken("valid-token", share.ShareID)); err != nil {
		t.Fatal(err)
	}

	handler := NewHandler(repo, tokenStore, nil)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/webdav/ocm/"+testWebDAVID+"/some-other-name.txt", nil)
	req.Header.Set("Authorization", "Bearer valid-token")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	if w.Body.String() != "hello" {
		t.Errorf("expected body %q, got %q", "hello", w.Body.String())
	}
}

func TestServeHTTP_BearerWithInvalidTokenFails401(t *testing.T) {
	t.Parallel()

	repo := newMockOutgoingShareRepo()
	_ = seedShare(t, repo)
	handler := NewHandler(repo, newMockTokenStore(), nil)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/webdav/ocm/"+testWebDAVID, nil)
	req.Header.Set("Authorization", "Bearer invalid-token")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}

	assertBearerWWWAuthenticate(t, w)
}

func TestServeHTTP_BearerWithExpiredTokenFails401(t *testing.T) {
	t.Parallel()

	repo := newMockOutgoingShareRepo()
	_ = seedShare(t, repo)

	tokenStore := newMockTokenStore()
	if err := tokenStore.Store(context.Background(), &token.IssuedToken{
		AccessToken: "expired-token",
		ShareID:     "share-1",
		ExpiresAt:   time.Now().Add(-time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	handler := NewHandler(repo, tokenStore, nil)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/webdav/ocm/"+testWebDAVID, nil)
	req.Header.Set("Authorization", "Bearer expired-token")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for expired token, got %d", w.Code)
	}

	assertBearerWWWAuthenticate(t, w)
}

func TestServeHTTP_BasicAuthRejected401(t *testing.T) {
	t.Parallel()

	repo := newMockOutgoingShareRepo()
	share := seedShare(t, repo)

	tokenStore := newMockTokenStore()
	if err := tokenStore.Store(context.Background(), unexpiredTestToken(share.SharedSecret, share.ShareID)); err != nil {
		t.Fatal(err)
	}

	handler := NewHandler(repo, tokenStore, nil)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/webdav/ocm/"+testWebDAVID, nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for Basic auth, got %d", w.Code)
	}

	assertBearerWWWAuthenticate(t, w)
}

// TestServeHTTP_NonStrictSharedSecretSucceeds covers the non-strict legacy sender
// fork at the HTTP layer: a non-strict share (Requirements omit
// must-exchange-token) authenticates with a sharedSecret Bearer and succeeds.
func TestServeHTTP_NonStrictSharedSecretSucceeds(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	filePath := filepath.Join(dir, "hello.txt")
	if err := os.WriteFile(filePath, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}

	repo := newMockOutgoingShareRepo()
	share := seedShare(t, repo)

	share.LocalPath = filePath
	if err := repo.Update(context.Background(), share); err != nil {
		t.Fatal(err)
	}

	handler := NewHandler(repo, newMockTokenStore(), nil)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/webdav/ocm/"+testWebDAVID+"/hello.txt", nil)
	req.Header.Set("Authorization", "Bearer "+share.SharedSecret)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for non-strict shared-secret bearer, got %d: %s", w.Code, w.Body.String())
	}
}
