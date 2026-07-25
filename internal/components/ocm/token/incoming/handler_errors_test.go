package incoming_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token"
	tokenincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token/incoming"
)

func TestHandler_InvalidCode(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	shareRepo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	tokenStore := token.NewMemoryTokenStore()
	handler := tokenincoming.NewHandler(shareRepo, tokenStore, enabledSettings(), enabledCodeFlow(), "https://local.example.com", logger)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", "receiver.example.com")
	form.Set("code", "nonexistent-secret")

	req := httptest.NewRequest(http.MethodPost, "/ocm/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	handler.HandleToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}

	var resp token.OAuthError
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Error != token.ErrorInvalidGrant {
		t.Errorf("expected error %q, got %q", token.ErrorInvalidGrant, resp.Error)
	}
}

func TestHandler_ClientMismatch(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	shareRepo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	tokenStore := token.NewMemoryTokenStore()
	handler := tokenincoming.NewHandler(shareRepo, tokenStore, enabledSettings(), enabledCodeFlow(), "https://local.example.com", logger)

	// Create a share
	share := &sharesoutgoing.OutgoingShare{
		ProviderID:   "provider-mismatch",
		WebDAVID:     "webdav-mismatch",
		SharedSecret: "secret-mismatch",
		ReceiverHost: "receiver.example.com",
		LocalPath:    "/tmp/test.txt",
	}
	shareRepo.Create(context.Background(), share)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", "wrong-receiver.example.com")
	form.Set("code", "secret-mismatch")

	req := httptest.NewRequest(http.MethodPost, "/ocm/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	handler.HandleToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}

	var resp token.OAuthError
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Error != token.ErrorInvalidClient {
		t.Errorf("expected error %q, got %q", token.ErrorInvalidClient, resp.Error)
	}
}

func TestTokenStore_Expiration(t *testing.T) {
	store := token.NewMemoryTokenStore()
	ctx := context.Background()

	// Store a token with very short TTL (already expired)
	expired := &token.IssuedToken{
		AccessToken: "expired-token",
		ShareID:     "share-1",
	}
	// Manually set to expired
	expired.ExpiresAt = expired.IssuedAt // already expired

	store.Store(ctx, expired)

	// Try to get it
	_, err := store.Get(ctx, "expired-token")
	if err != token.ErrTokenExpired {
		t.Errorf("expected ErrTokenExpired, got %v", err)
	}
}

func TestGenerateAccessToken(t *testing.T) {
	token1, err := token.GenerateAccessToken()
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	token2, err := token.GenerateAccessToken()
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	if token1 == token2 {
		t.Error("generated tokens should be unique")
	}

	if len(token1) != 64 { // 32 bytes = 64 hex chars
		t.Errorf("expected 64 char token, got %d", len(token1))
	}
}
