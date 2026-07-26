package incoming_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token"
	tokenincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token/incoming"
)

func TestHandler_FormEncoded_Success(t *testing.T) {
	shareRepo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	tokenStore := token.NewMemoryTokenStore()
	handler := tokenincoming.NewHandler(shareRepo, tokenStore, enabledSettings(), enabledCodeFlow(), "https://local.example.com")

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
	shareRepo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	tokenStore := token.NewMemoryTokenStore()
	handler := tokenincoming.NewHandler(shareRepo, tokenStore, enabledSettings(), enabledCodeFlow(), "https://local.example.com")

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
