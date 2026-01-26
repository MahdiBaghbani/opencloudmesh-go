package token_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token"
)

// enabledSettings returns token exchange settings with enabled=true for testing.
func enabledSettings() *token.TokenExchangeSettings {
	s := &token.TokenExchangeSettings{Enabled: true}
	s.ApplyDefaults()
	return s
}

func TestHandler_FormEncoded_Success(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	shareRepo := shares.NewMemoryOutgoingShareRepo()
	tokenStore := token.NewMemoryTokenStore()
	handler := token.NewHandler(shareRepo, tokenStore, enabledSettings(), "https://local.example.com", logger)

	// Create a share
	share := &shares.OutgoingShare{
		ProviderID:   "provider-123",
		WebDAVID:     "webdav-456",
		SharedSecret: "secret-code-789",
		ReceiverHost: "receiver.example.com",
		LocalPath:    "/tmp/test.txt",
	}
	shareRepo.Create(context.Background(), share)

	// Make token request
	form := url.Values{}
	form.Set("grant_type", "ocm_share")
	form.Set("client_id", "receiver.example.com")
	form.Set("code", "secret-code-789")

	req := httptest.NewRequest(http.MethodPost, "/ocm/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	handler.HandleToken(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp token.TokenResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.AccessToken == "" {
		t.Error("access_token is empty")
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("token_type = %q, want %q", resp.TokenType, "Bearer")
	}
	if resp.ExpiresIn <= 0 {
		t.Errorf("expires_in = %d, want > 0", resp.ExpiresIn)
	}

	// Verify token is stored
	stored, err := tokenStore.Get(context.Background(), resp.AccessToken)
	if err != nil {
		t.Errorf("failed to get stored token: %v", err)
	}
	if stored.ShareID != share.ShareID {
		t.Errorf("stored shareId mismatch")
	}
}

func TestHandler_JSON_NextcloudInterop(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	shareRepo := shares.NewMemoryOutgoingShareRepo()
	tokenStore := token.NewMemoryTokenStore()
	handler := token.NewHandler(shareRepo, tokenStore, enabledSettings(), "https://local.example.com", logger)

	// Create a share
	share := &shares.OutgoingShare{
		ProviderID:   "provider-nc",
		WebDAVID:     "webdav-nc",
		SharedSecret: "nc-secret",
		ReceiverHost: "nextcloud.example.com",
		LocalPath:    "/tmp/test.txt",
	}
	shareRepo.Create(context.Background(), share)

	// Make token request with JSON body (Nextcloud style)
	body := `{"grant_type":"ocm_share","client_id":"nextcloud.example.com","code":"nc-secret"}`

	req := httptest.NewRequest(http.MethodPost, "/ocm/token", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.HandleToken(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp token.TokenResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.AccessToken == "" {
		t.Error("access_token is empty")
	}
}

func TestHandler_MissingFields(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	shareRepo := shares.NewMemoryOutgoingShareRepo()
	tokenStore := token.NewMemoryTokenStore()
	handler := token.NewHandler(shareRepo, tokenStore, enabledSettings(), "https://local.example.com", logger)

	tests := []struct {
		name string
		form url.Values
	}{
		{"missing grant_type", url.Values{"client_id": {"x"}, "code": {"y"}}},
		{"missing client_id", url.Values{"grant_type": {"ocm_share"}, "code": {"y"}}},
		{"missing code", url.Values{"grant_type": {"ocm_share"}, "client_id": {"x"}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/ocm/token", strings.NewReader(tt.form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()

			handler.HandleToken(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("expected 400, got %d", w.Code)
			}

			var resp token.OAuthError
			json.NewDecoder(w.Body).Decode(&resp)
			if resp.Error != token.ErrorInvalidRequest {
				t.Errorf("expected error %q, got %q", token.ErrorInvalidRequest, resp.Error)
			}
		})
	}
}

func TestHandler_InvalidGrantType(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	shareRepo := shares.NewMemoryOutgoingShareRepo()
	tokenStore := token.NewMemoryTokenStore()
	handler := token.NewHandler(shareRepo, tokenStore, enabledSettings(), "https://local.example.com", logger)

	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("client_id", "x")
	form.Set("code", "y")

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

func TestHandler_InvalidCode(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	shareRepo := shares.NewMemoryOutgoingShareRepo()
	tokenStore := token.NewMemoryTokenStore()
	handler := token.NewHandler(shareRepo, tokenStore, enabledSettings(), "https://local.example.com", logger)

	form := url.Values{}
	form.Set("grant_type", "ocm_share")
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
	shareRepo := shares.NewMemoryOutgoingShareRepo()
	tokenStore := token.NewMemoryTokenStore()
	handler := token.NewHandler(shareRepo, tokenStore, enabledSettings(), "https://local.example.com", logger)

	// Create a share
	share := &shares.OutgoingShare{
		ProviderID:   "provider-mismatch",
		WebDAVID:     "webdav-mismatch",
		SharedSecret: "secret-mismatch",
		ReceiverHost: "receiver.example.com",
		LocalPath:    "/tmp/test.txt",
	}
	shareRepo.Create(context.Background(), share)

	form := url.Values{}
	form.Set("grant_type", "ocm_share")
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

func TestHandler_ClientID_DefaultPortEquivalence(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	shareRepo := shares.NewMemoryOutgoingShareRepo()
	tokenStore := token.NewMemoryTokenStore()

	tests := []struct {
		name           string
		externalOrigin string
		receiverHost   string
		clientID       string
		wantMatch      bool
	}{
		{
			name:           "https: bare host matches host:443",
			externalOrigin: "https://local.example.com",
			receiverHost:   "receiver.example.com",
			clientID:       "receiver.example.com:443",
			wantMatch:      true,
		},
		{
			name:           "https: host:443 matches bare host",
			externalOrigin: "https://local.example.com",
			receiverHost:   "receiver.example.com:443",
			clientID:       "receiver.example.com",
			wantMatch:      true,
		},
		{
			name:           "http: bare host matches host:80",
			externalOrigin: "http://local.example.com",
			receiverHost:   "receiver.example.com",
			clientID:       "receiver.example.com:80",
			wantMatch:      true,
		},
		{
			name:           "https: bare host does NOT match host:80",
			externalOrigin: "https://local.example.com",
			receiverHost:   "receiver.example.com",
			clientID:       "receiver.example.com:80",
			wantMatch:      false,
		},
		{
			name:           "exact match still works",
			externalOrigin: "https://local.example.com",
			receiverHost:   "receiver.example.com",
			clientID:       "receiver.example.com",
			wantMatch:      true,
		},
		{
			name:           "case normalization",
			externalOrigin: "https://local.example.com",
			receiverHost:   "RECEIVER.EXAMPLE.COM",
			clientID:       "receiver.example.com",
			wantMatch:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := token.NewHandler(shareRepo, tokenStore, enabledSettings(), tt.externalOrigin, logger)

			share := &shares.OutgoingShare{
				ProviderID:   "provider-port-test",
				WebDAVID:     "webdav-port-test",
				SharedSecret: "port-test-secret-" + tt.name,
				ReceiverHost: tt.receiverHost,
				LocalPath:    "/tmp/test.txt",
			}
			shareRepo.Create(context.Background(), share)

			form := url.Values{}
			form.Set("grant_type", "ocm_share")
			form.Set("client_id", tt.clientID)
			form.Set("code", "port-test-secret-"+tt.name)

			req := httptest.NewRequest(http.MethodPost, "/ocm/token", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()

			handler.HandleToken(w, req)

			if tt.wantMatch {
				if w.Code != http.StatusOK {
					t.Errorf("expected 200 (match), got %d: %s", w.Code, w.Body.String())
				}
			} else {
				if w.Code != http.StatusBadRequest {
					t.Errorf("expected 400 (mismatch), got %d: %s", w.Code, w.Body.String())
				}
			}
		})
	}
}

func TestHandler_DisabledReturns501(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	shareRepo := shares.NewMemoryOutgoingShareRepo()
	tokenStore := token.NewMemoryTokenStore()

	// Create handler with token exchange disabled
	disabledSettings := &token.TokenExchangeSettings{Enabled: false}
	disabledSettings.ApplyDefaults()
	handler := token.NewHandler(shareRepo, tokenStore, disabledSettings, "https://local.example.com", logger)

	form := url.Values{}
	form.Set("grant_type", "ocm_share")
	form.Set("client_id", "receiver.example.com")
	form.Set("code", "secret-code")

	req := httptest.NewRequest(http.MethodPost, "/ocm/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	handler.HandleToken(w, req)

	if w.Code != http.StatusNotImplemented {
		t.Errorf("expected 501, got %d: %s", w.Code, w.Body.String())
	}

	var resp token.OAuthError
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Error != "not_implemented" {
		t.Errorf("expected error 'not_implemented', got %q", resp.Error)
	}
}
