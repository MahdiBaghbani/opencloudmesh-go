package incoming_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	inboundsignature "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/inbound/signature"
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token"
	tokenincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token/incoming"
)

func TestHandler_ClientID_DefaultPortEquivalence(t *testing.T) {
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
			handler := tokenincoming.NewHandler(shareRepo, tokenStore, enabledSettings(), enabledCodeFlow(), tt.publicOrigin)

			share := &sharesoutgoing.OutgoingShare{
				ProviderID:   "provider-port-test",
				WebDAVID:     "webdav-port-test",
				SharedSecret: "port-test-secret-" + tt.name,
				ReceiverHost: tt.receiverHost,
				LocalPath:    "/tmp/test.txt",
			}
			if err := shareRepo.Create(context.Background(), share); err != nil {
				t.Fatalf("Create: %v", err)
			}

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
	shareRepo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	tokenStore := token.NewMemoryTokenStore()
	handler := tokenincoming.NewHandler(shareRepo, tokenStore, enabledSettings(), enabledCodeFlow(), "")

	share := &sharesoutgoing.OutgoingShare{
		ProviderID:   "provider-empty-origin",
		WebDAVID:     "webdav-empty-origin",
		SharedSecret: "empty-origin-secret",
		ReceiverHost: "receiver.example.com",
		LocalPath:    "/tmp/test.txt",
	}
	if err := shareRepo.Create(context.Background(), share); err != nil {
		t.Fatalf("Create: %v", err)
	}

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
	shareRepo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	tokenStore := token.NewMemoryTokenStore()

	nilCodeFlowSettings := &tokenincoming.TokenExchangeSettings{}
	nilCodeFlowSettings.ApplyDefaults()
	handler := tokenincoming.NewHandler(shareRepo, tokenStore, nilCodeFlowSettings, nil, "https://local.example.com")

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
	shareRepo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	tokenStore := token.NewMemoryTokenStore()
	handler := tokenincoming.NewHandler(shareRepo, tokenStore, enabledSettings(), enabledCodeFlow(), "https://local.example.com")

	share := &sharesoutgoing.OutgoingShare{
		ProviderID:   "provider-identity-match",
		WebDAVID:     "webdav-identity-match",
		SharedSecret: "identity-match-secret",
		ReceiverHost: "receiver.example.com",
		LocalPath:    "/tmp/test.txt",
	}
	if err := shareRepo.Create(context.Background(), share); err != nil {
		t.Fatalf("Create: %v", err)
	}

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
	shareRepo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	tokenStore := token.NewMemoryTokenStore()
	handler := tokenincoming.NewHandler(shareRepo, tokenStore, enabledSettings(), enabledCodeFlow(), "https://local.example.com")

	share := &sharesoutgoing.OutgoingShare{
		ProviderID:   "provider-identity-mismatch",
		WebDAVID:     "webdav-identity-mismatch",
		SharedSecret: "identity-mismatch-secret",
		ReceiverHost: "receiver.example.com",
		LocalPath:    "/tmp/test.txt",
	}
	if err := shareRepo.Create(context.Background(), share); err != nil {
		t.Fatalf("Create: %v", err)
	}

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
