package incoming_test

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

	inboundsignature "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/inbound/signature"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token"
	tokenincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token/incoming"
)

// enabledSettings returns token exchange path settings for testing.
func enabledSettings() *tokenincoming.TokenExchangeSettings {
	s := &tokenincoming.TokenExchangeSettings{}
	s.ApplyDefaults()
	return s
}

func enabledCodeFlow() *policy.CodeFlow {
	return policy.NewCodeFlow()
}

func TestHandler_FormEncoded_Success(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	shareRepo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	tokenStore := token.NewMemoryTokenStore()
	handler := tokenincoming.NewHandler(shareRepo, tokenStore, enabledSettings(), enabledCodeFlow(), "https://local.example.com", logger)

	// Create a share
	share := &sharesoutgoing.OutgoingShare{
		ProviderID:   "provider-123",
		WebDAVID:     "webdav-456",
		SharedSecret: "secret-code-789",
		ReceiverHost: "receiver.example.com",
		LocalPath:    "/tmp/test.txt",
	}
	shareRepo.Create(context.Background(), share)

	// Make token request using the canonical authorization_code grant.
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", "receiver.example.com")
	form.Set("code", "secret-code-789")

	req := httptest.NewRequest(http.MethodPost, "/ocm/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	handler.HandleToken(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want %q", got, "no-store")
	}
	if got := w.Header().Get("Pragma"); got != "no-cache" {
		t.Errorf("Pragma = %q, want %q", got, "no-cache")
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want prefix %q", ct, "application/json")
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

func TestHandler_AuthorizationCode_FormEncoded_Success(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	shareRepo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	tokenStore := token.NewMemoryTokenStore()
	handler := tokenincoming.NewHandler(shareRepo, tokenStore, enabledSettings(), enabledCodeFlow(), "https://local.example.com", logger)

	share := &sharesoutgoing.OutgoingShare{
		ProviderID:   "provider-ac",
		WebDAVID:     "webdav-ac",
		SharedSecret: "ac-secret-code",
		ReceiverHost: "receiver.example.com",
		LocalPath:    "/tmp/test.txt",
	}
	shareRepo.Create(context.Background(), share)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", "receiver.example.com")
	form.Set("code", "ac-secret-code")

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
}

func TestHandler_MissingFields(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	shareRepo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	tokenStore := token.NewMemoryTokenStore()
	handler := tokenincoming.NewHandler(shareRepo, tokenStore, enabledSettings(), enabledCodeFlow(), "https://local.example.com", logger)

	tests := []struct {
		name string
		form url.Values
	}{
		{"missing grant_type", url.Values{"client_id": {"x"}, "code": {"y"}}},
		{"missing client_id", url.Values{"grant_type": {"authorization_code"}, "code": {"y"}}},
		{"missing code", url.Values{"grant_type": {"authorization_code"}, "client_id": {"x"}}},
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
	shareRepo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	tokenStore := token.NewMemoryTokenStore()
	handler := tokenincoming.NewHandler(shareRepo, tokenStore, enabledSettings(), enabledCodeFlow(), "https://local.example.com", logger)

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
	if resp.Error != token.ErrorUnsupportedGrantType {
		t.Errorf("expected error %q, got %q", token.ErrorUnsupportedGrantType, resp.Error)
	}
}

// TestHandler_UnsupportedGrantType_Rejected proves the strict token contract
// rejects unknown grant types with unsupported_grant_type.
func TestHandler_UnsupportedGrantType_Rejected(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	shareRepo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	tokenStore := token.NewMemoryTokenStore()
	handler := tokenincoming.NewHandler(shareRepo, tokenStore, enabledSettings(), enabledCodeFlow(), "https://local.example.com", logger)

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", "receiver.example.com")
	form.Set("code", "secret-code")

	req := httptest.NewRequest(http.MethodPost, "/ocm/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	handler.HandleToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}

	var resp token.OAuthError
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Error != token.ErrorUnsupportedGrantType {
		t.Errorf("expected error %q, got %q", token.ErrorUnsupportedGrantType, resp.Error)
	}
}

// TestHandler_JSONBody_Rejected proves JSON token request bodies are rejected.
func TestHandler_JSONBody_Rejected(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	shareRepo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	tokenStore := token.NewMemoryTokenStore()
	handler := tokenincoming.NewHandler(shareRepo, tokenStore, enabledSettings(), enabledCodeFlow(), "https://local.example.com", logger)

	body := `{"grant_type":"authorization_code","client_id":"receiver.example.com","code":"secret-code"}`
	req := httptest.NewRequest(http.MethodPost, "/ocm/token", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.HandleToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}

	var resp token.OAuthError
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Error != token.ErrorInvalidRequest {
		t.Errorf("expected error %q, got %q", token.ErrorInvalidRequest, resp.Error)
	}
}

func TestHandler_ContentTypeValidation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	tests := []struct {
		name               string
		contentType        string
		omitContentType    bool
		wantStatus         int
		wantInvalidRequest bool
	}{
		{
			name:        "canonical form urlencoded",
			contentType: "application/x-www-form-urlencoded",
			wantStatus:  http.StatusOK,
		},
		{
			name:        "form urlencoded with charset",
			contentType: "application/x-www-form-urlencoded; charset=utf-8",
			wantStatus:  http.StatusOK,
		},
		{
			name:        "mixed case media type",
			contentType: "Application/x-www-Form-Urlencoded",
			wantStatus:  http.StatusOK,
		},
		{
			name:        "upper case media type",
			contentType: "APPLICATION/X-WWW-FORM-URLENCODED",
			wantStatus:  http.StatusOK,
		},
		{
			name:               "omitted content type header",
			omitContentType:    true,
			wantStatus:         http.StatusBadRequest,
			wantInvalidRequest: true,
		},
		{
			name:               "text plain",
			contentType:        "text/plain",
			wantStatus:         http.StatusBadRequest,
			wantInvalidRequest: true,
		},
		{
			name:               "application json",
			contentType:        "application/json",
			wantStatus:         http.StatusBadRequest,
			wantInvalidRequest: true,
		},
		{
			name:               "bogus form urlencoded suffix",
			contentType:        "application/x-www-form-urlencoded-bogus",
			wantStatus:         http.StatusBadRequest,
			wantInvalidRequest: true,
		},
		{
			name:               "malformed charset parameter",
			contentType:        "application/x-www-form-urlencoded; charset=",
			wantStatus:         http.StatusBadRequest,
			wantInvalidRequest: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shareRepo := sharesoutgoing.NewMemoryOutgoingShareRepo()
			tokenStore := token.NewMemoryTokenStore()
			handler := tokenincoming.NewHandler(shareRepo, tokenStore, enabledSettings(), enabledCodeFlow(), "https://local.example.com", logger)

			sharedSecret := "content-type-secret-" + tt.name
			if tt.wantStatus == http.StatusOK {
				share := &sharesoutgoing.OutgoingShare{
					ProviderID:   "provider-content-type",
					WebDAVID:     "webdav-content-type",
					SharedSecret: sharedSecret,
					ReceiverHost: "receiver.example.com",
					LocalPath:    "/tmp/test.txt",
				}
				shareRepo.Create(context.Background(), share)
			}

			form := url.Values{}
			form.Set("grant_type", "authorization_code")
			form.Set("client_id", "receiver.example.com")
			if tt.wantStatus == http.StatusOK {
				form.Set("code", sharedSecret)
			} else {
				form.Set("code", "arbitrary-code")
			}

			req := httptest.NewRequest(http.MethodPost, "/ocm/token", strings.NewReader(form.Encode()))
			if !tt.omitContentType {
				req.Header.Set("Content-Type", tt.contentType)
			}

			w := httptest.NewRecorder()
			handler.HandleToken(w, req)

			if w.Code != tt.wantStatus {
				t.Fatalf("expected %d, got %d: %s", tt.wantStatus, w.Code, w.Body.String())
			}

			if tt.wantInvalidRequest {
				var resp token.OAuthError
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				if resp.Error != token.ErrorInvalidRequest {
					t.Errorf("expected error %q, got %q", token.ErrorInvalidRequest, resp.Error)
				}
				return
			}

			var resp token.TokenResponse
			if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
				t.Fatalf("failed to decode response: %v", err)
			}
			if resp.AccessToken == "" {
				t.Error("access_token is empty")
			}
		})
	}
}

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

func TestHandler_ClientID_DefaultPortEquivalence(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	shareRepo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	tokenStore := token.NewMemoryTokenStore()

	tests := []struct {
		name         string
		publicOrigin string
		receiverHost string
		clientID     string
		wantMatch    bool
	}{
		{
			name:         "https: bare host matches host:443",
			publicOrigin: "https://local.example.com",
			receiverHost: "receiver.example.com",
			clientID:     "receiver.example.com:443",
			wantMatch:    true,
		},
		{
			name:         "https: host:443 matches bare host",
			publicOrigin: "https://local.example.com",
			receiverHost: "receiver.example.com:443",
			clientID:     "receiver.example.com",
			wantMatch:    true,
		},
		{
			name:         "http: bare host matches host:80",
			publicOrigin: "http://local.example.com",
			receiverHost: "receiver.example.com",
			clientID:     "receiver.example.com:80",
			wantMatch:    true,
		},
		{
			name:         "https: bare host does NOT match host:80",
			publicOrigin: "https://local.example.com",
			receiverHost: "receiver.example.com",
			clientID:     "receiver.example.com:80",
			wantMatch:    false,
		},
		{
			name:         "exact match still works",
			publicOrigin: "https://local.example.com",
			receiverHost: "receiver.example.com",
			clientID:     "receiver.example.com",
			wantMatch:    true,
		},
		{
			name:         "case normalization",
			publicOrigin: "https://local.example.com",
			receiverHost: "RECEIVER.EXAMPLE.COM",
			clientID:     "receiver.example.com",
			wantMatch:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := tokenincoming.NewHandler(shareRepo, tokenStore, enabledSettings(), enabledCodeFlow(), tt.publicOrigin, logger)

			share := &sharesoutgoing.OutgoingShare{
				ProviderID:   "provider-port-test",
				WebDAVID:     "webdav-port-test",
				SharedSecret: "port-test-secret-" + tt.name,
				ReceiverHost: tt.receiverHost,
				LocalPath:    "/tmp/test.txt",
			}
			shareRepo.Create(context.Background(), share)

			form := url.Values{}
			form.Set("grant_type", "authorization_code")
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

// TestHandler_EmptyPublicOrigin_HTTPSDefault proves the token handler keeps the
// https-default scheme semantics even after centralizing parsing. With an empty
// publicOrigin, localScheme defaults to "https", so client_id
// "receiver.example.com:443" collapses to the bare "receiver.example.com"
// receiver host and the exchange succeeds. An empty scheme would preserve :443
// and cause an invalid_client mismatch.
func TestHandler_EmptyPublicOrigin_HTTPSDefault(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	shareRepo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	tokenStore := token.NewMemoryTokenStore()
	handler := tokenincoming.NewHandler(shareRepo, tokenStore, enabledSettings(), enabledCodeFlow(), "", logger)

	share := &sharesoutgoing.OutgoingShare{
		ProviderID:   "provider-empty-origin",
		WebDAVID:     "webdav-empty-origin",
		SharedSecret: "empty-origin-secret",
		ReceiverHost: "receiver.example.com",
		LocalPath:    "/tmp/test.txt",
	}
	shareRepo.Create(context.Background(), share)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", "receiver.example.com:443")
	form.Set("code", "empty-origin-secret")

	req := httptest.NewRequest(http.MethodPost, "/ocm/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	handler.HandleToken(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (https default strips :443, so match), got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandler_NilCodeFlowReturns501(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	shareRepo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	tokenStore := token.NewMemoryTokenStore()

	nilCodeFlowSettings := &tokenincoming.TokenExchangeSettings{}
	nilCodeFlowSettings.ApplyDefaults()
	handler := tokenincoming.NewHandler(shareRepo, tokenStore, nilCodeFlowSettings, nil, "https://local.example.com", logger)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
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

func TestHandler_VerifiedPeerIdentityMatch(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	shareRepo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	tokenStore := token.NewMemoryTokenStore()
	handler := tokenincoming.NewHandler(shareRepo, tokenStore, enabledSettings(), enabledCodeFlow(), "https://local.example.com", logger)

	share := &sharesoutgoing.OutgoingShare{
		ProviderID:   "provider-identity-match",
		WebDAVID:     "webdav-identity-match",
		SharedSecret: "identity-match-secret",
		ReceiverHost: "receiver.example.com",
		LocalPath:    "/tmp/test.txt",
	}
	shareRepo.Create(context.Background(), share)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", "receiver.example.com")
	form.Set("code", "identity-match-secret")

	req := httptest.NewRequest(http.MethodPost, "/ocm/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx := context.WithValue(req.Context(), inboundsignature.PeerIdentityKey, &inboundsignature.PeerIdentity{
		AuthorityForCompare: "receiver.example.com",
		Authenticated:       true,
	})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handler.HandleToken(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 when verified identity matches receiver, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandler_VerifiedPeerIdentityMismatch(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	shareRepo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	tokenStore := token.NewMemoryTokenStore()
	handler := tokenincoming.NewHandler(shareRepo, tokenStore, enabledSettings(), enabledCodeFlow(), "https://local.example.com", logger)

	share := &sharesoutgoing.OutgoingShare{
		ProviderID:   "provider-identity-mismatch",
		WebDAVID:     "webdav-identity-mismatch",
		SharedSecret: "identity-mismatch-secret",
		ReceiverHost: "receiver.example.com",
		LocalPath:    "/tmp/test.txt",
	}
	shareRepo.Create(context.Background(), share)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", "receiver.example.com")
	form.Set("code", "identity-mismatch-secret")

	req := httptest.NewRequest(http.MethodPost, "/ocm/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx := context.WithValue(req.Context(), inboundsignature.PeerIdentityKey, &inboundsignature.PeerIdentity{
		AuthorityForCompare: "other.example.com",
		Authenticated:       true,
	})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handler.HandleToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when verified identity mismatches receiver, got %d: %s", w.Code, w.Body.String())
	}

	var resp token.OAuthError
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Error != token.ErrorInvalidClient {
		t.Errorf("expected error %q, got %q", token.ErrorInvalidClient, resp.Error)
	}
}
