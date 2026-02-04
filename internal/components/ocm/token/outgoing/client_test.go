// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package outgoing_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/outboundsigning"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peercompat"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token"
	tokenoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
)

// mockSigner is a test signer that adds a mock signature header.
type mockSigner struct {
	failSign bool
}

func (s *mockSigner) Sign(req *http.Request) error {
	if s.failSign {
		return &peercompat.ClassifiedError{
			ReasonCode: peercompat.ReasonSignatureInvalid,
			Message:    "signing failed",
		}
	}
	req.Header.Set("Signature", "mock-signature")
	return nil
}

// makePolicy creates an OutboundPolicy for testing.
func makePolicy(outboundMode string, profileRegistry *peercompat.ProfileRegistry) *outboundsigning.OutboundPolicy {
	return &outboundsigning.OutboundPolicy{
		OutboundMode:        outboundMode,
		PeerProfileOverride: "non-strict",
		ProfileRegistry:     profileRegistry,
	}
}

func TestClient_Exchange_Success(t *testing.T) {
	// Create mock server that returns a valid token
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}

		// Verify it's form-urlencoded
		if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Errorf("expected form-urlencoded, got %s", r.Header.Get("Content-Type"))
		}

		// Verify signature header exists
		if r.Header.Get("Signature") == "" {
			t.Error("expected Signature header")
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(token.TokenResponse{
			AccessToken: "test-access-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	}))
	defer server.Close()

	httpClient := httpclient.NewContextClient(httpclient.New(&config.OutboundHTTPConfig{
		SSRFMode: "off",
	}, nil))

	client := tokenoutgoing.NewClient(
		httpClient,
		&mockSigner{},
		makePolicy("strict", nil),
		"my-instance.example.com",
	)

	result, err := client.Exchange(context.Background(), tokenoutgoing.ExchangeRequest{
		TokenEndPoint: server.URL,
		PeerDomain:    "peer.example.com",
		SharedSecret:  "test-secret",
	})

	if err != nil {
		t.Fatalf("Exchange failed: %v", err)
	}
	if result.AccessToken != "test-access-token" {
		t.Errorf("expected access_token 'test-access-token', got %s", result.AccessToken)
	}
	if result.TokenType != "Bearer" {
		t.Errorf("expected token_type 'Bearer', got %s", result.TokenType)
	}
	if result.QuirkApplied != "" {
		t.Errorf("expected no quirk applied, got %s", result.QuirkApplied)
	}
}

func TestClient_Exchange_OutboundModeOff(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Should NOT have a signature header when mode is off
		if r.Header.Get("Signature") != "" {
			t.Error("should not have Signature header in off mode")
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(token.TokenResponse{
			AccessToken: "unsigned-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	}))
	defer server.Close()

	httpClient := httpclient.NewContextClient(httpclient.New(&config.OutboundHTTPConfig{
		SSRFMode: "off",
	}, nil))

	// OutboundMode "off" should skip signing
	client := tokenoutgoing.NewClient(
		httpClient,
		&mockSigner{},
		makePolicy("off", nil),
		"my-instance.example.com",
	)

	result, err := client.Exchange(context.Background(), tokenoutgoing.ExchangeRequest{
		TokenEndPoint: server.URL,
		PeerDomain:    "peer.example.com",
		SharedSecret:  "test-secret",
	})

	if err != nil {
		t.Fatalf("Exchange failed: %v", err)
	}
	if result.AccessToken != "unsigned-token" {
		t.Errorf("expected 'unsigned-token', got %s", result.AccessToken)
	}
}

func TestClient_Exchange_StrictModeWithSigner(t *testing.T) {
	// Create mock server that requires signed requests
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Signature") == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(token.OAuthError{
				Error:            token.ErrorUnauthorized,
				ErrorDescription: "signature required",
			})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(token.TokenResponse{
			AccessToken: "signed-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	}))
	defer server.Close()

	httpClient := httpclient.NewContextClient(httpclient.New(&config.OutboundHTTPConfig{
		SSRFMode: "off",
	}, nil))

	// Strict mode with working signer should succeed
	client := tokenoutgoing.NewClient(
		httpClient,
		&mockSigner{},
		makePolicy("strict", nil),
		"my-instance.example.com",
	)

	result, err := client.Exchange(context.Background(), tokenoutgoing.ExchangeRequest{
		TokenEndPoint: server.URL,
		PeerDomain:    "peer.example.com",
		SharedSecret:  "test-secret",
	})

	if err != nil {
		t.Fatalf("Exchange should succeed with signature: %v", err)
	}
	if result.AccessToken != "signed-token" {
		t.Errorf("expected 'signed-token', got %s", result.AccessToken)
	}
}

func TestClient_Exchange_TokenOnlyMode(t *testing.T) {
	// Create mock server that verifies signing
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Token-only mode should sign token exchange
		if r.Header.Get("Signature") == "" {
			t.Error("expected Signature header in token-only mode for token exchange")
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(token.TokenResponse{
			AccessToken: "token-only-signed",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	}))
	defer server.Close()

	httpClient := httpclient.NewContextClient(httpclient.New(&config.OutboundHTTPConfig{
		SSRFMode: "off",
	}, nil))

	// token-only should sign token exchange
	client := tokenoutgoing.NewClient(
		httpClient,
		&mockSigner{},
		makePolicy("token-only", nil),
		"my-instance.example.com",
	)

	result, err := client.Exchange(context.Background(), tokenoutgoing.ExchangeRequest{
		TokenEndPoint: server.URL,
		PeerDomain:    "peer.example.com",
		SharedSecret:  "test-secret",
	})

	if err != nil {
		t.Fatalf("Exchange failed: %v", err)
	}
	if result.AccessToken != "token-only-signed" {
		t.Errorf("expected 'token-only-signed', got %s", result.AccessToken)
	}
}

func TestClient_Exchange_CriteriaOnlyMode(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// criteria-only mode should sign token exchange (token exchange is always signed unless off)
		if r.Header.Get("Signature") == "" {
			t.Error("expected Signature header in criteria-only mode for token exchange")
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(token.TokenResponse{
			AccessToken: "criteria-only-signed",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	}))
	defer server.Close()

	httpClient := httpclient.NewContextClient(httpclient.New(&config.OutboundHTTPConfig{
		SSRFMode: "off",
	}, nil))

	client := tokenoutgoing.NewClient(
		httpClient,
		&mockSigner{},
		makePolicy("criteria-only", nil),
		"my-instance.example.com",
	)

	result, err := client.Exchange(context.Background(), tokenoutgoing.ExchangeRequest{
		TokenEndPoint: server.URL,
		PeerDomain:    "peer.example.com",
		SharedSecret:  "test-secret",
	})

	if err != nil {
		t.Fatalf("Exchange failed: %v", err)
	}
	if result.AccessToken != "criteria-only-signed" {
		t.Errorf("expected 'criteria-only-signed', got %s", result.AccessToken)
	}
}

func TestClient_Exchange_PeerProfileQuirk(t *testing.T) {
	// Create mock server that accepts unsigned requests
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// With accept_plain_token quirk, OutboundPolicy skips signing upfront
		// so we should get an unsigned request directly
		if r.Header.Get("Signature") != "" {
			t.Error("expected unsigned request when accept_plain_token quirk applies")
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(token.TokenResponse{
			AccessToken: "unsigned-quirk-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	}))
	defer server.Close()

	httpClient := httpclient.NewContextClient(httpclient.New(&config.OutboundHTTPConfig{
		SSRFMode: "off",
	}, nil))

	// Set up profile registry with nextcloud profile (has accept_plain_token quirk)
	mappings := []peercompat.ProfileMapping{
		{Pattern: "nextcloud.example.com", ProfileName: "nextcloud"},
	}
	profileRegistry := peercompat.NewProfileRegistry(nil, mappings)

	// With accept_plain_token quirk, OutboundPolicy tells us to skip signing
	client := tokenoutgoing.NewClient(
		httpClient,
		&mockSigner{},
		makePolicy("criteria-only", profileRegistry),
		"my-instance.example.com",
	)

	result, err := client.Exchange(context.Background(), tokenoutgoing.ExchangeRequest{
		TokenEndPoint: server.URL,
		PeerDomain:    "nextcloud.example.com",
		SharedSecret:  "test-secret",
	})

	if err != nil {
		t.Fatalf("Exchange should succeed with quirk: %v", err)
	}
	if result.AccessToken != "unsigned-quirk-token" {
		t.Errorf("expected 'unsigned-quirk-token', got %s", result.AccessToken)
	}
	// Note: QuirkApplied is only set when we fallback from signed -> unsigned
	// With OutboundPolicy, the decision is made upfront so no fallback occurs
}

func TestClient_Exchange_OAuthError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(token.OAuthError{
			Error:            token.ErrorInvalidGrant,
			ErrorDescription: "invalid code",
		})
	}))
	defer server.Close()

	httpClient := httpclient.NewContextClient(httpclient.New(&config.OutboundHTTPConfig{
		SSRFMode: "off",
	}, nil))

	client := tokenoutgoing.NewClient(
		httpClient,
		nil,
		makePolicy("off", nil),
		"my-instance.example.com",
	)

	_, err := client.Exchange(context.Background(), tokenoutgoing.ExchangeRequest{
		TokenEndPoint: server.URL,
		PeerDomain:    "peer.example.com",
		SharedSecret:  "bad-secret",
	})

	if err == nil {
		t.Fatal("expected error for invalid grant")
	}

	// Check it's properly classified
	var ce *peercompat.ClassifiedError
	if !isClassifiedError(err, &ce) {
		t.Errorf("expected ClassifiedError, got %T", err)
	}
}

func TestClient_Exchange_DefaultGrantType_AuthorizationCode(t *testing.T) {
	// With no profile override (strict/off), default grant_type is authorization_code.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("failed to parse form: %v", err)
		}
		got := r.FormValue("grant_type")
		if got != "authorization_code" {
			t.Errorf("grant_type = %q, want %q", got, "authorization_code")
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(token.TokenResponse{
			AccessToken: "ac-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	}))
	defer server.Close()

	httpClient := httpclient.NewContextClient(httpclient.New(&config.OutboundHTTPConfig{
		SSRFMode: "off",
	}, nil))

	client := tokenoutgoing.NewClient(
		httpClient,
		nil,
		makePolicy("off", nil),
		"my-instance.example.com",
	)

	result, err := client.Exchange(context.Background(), tokenoutgoing.ExchangeRequest{
		TokenEndPoint: server.URL,
		PeerDomain:    "peer.example.com",
		SharedSecret:  "test-secret",
	})

	if err != nil {
		t.Fatalf("Exchange failed: %v", err)
	}
	if result.AccessToken != "ac-token" {
		t.Errorf("expected 'ac-token', got %s", result.AccessToken)
	}
}

func TestClient_Exchange_NextcloudProfile_OCMShareGrantType(t *testing.T) {
	// Nextcloud profile overrides grant_type to ocm_share.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("failed to parse form: %v", err)
		}
		got := r.FormValue("grant_type")
		if got != "ocm_share" {
			t.Errorf("grant_type = %q, want %q", got, "ocm_share")
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(token.TokenResponse{
			AccessToken: "nc-compat-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	}))
	defer server.Close()

	httpClient := httpclient.NewContextClient(httpclient.New(&config.OutboundHTTPConfig{
		SSRFMode: "off",
	}, nil))

	mappings := []peercompat.ProfileMapping{
		{Pattern: "nextcloud.example.com", ProfileName: "nextcloud"},
	}
	profileRegistry := peercompat.NewProfileRegistry(nil, mappings)

	client := tokenoutgoing.NewClient(
		httpClient,
		&mockSigner{},
		makePolicy("criteria-only", profileRegistry),
		"my-instance.example.com",
	)

	result, err := client.Exchange(context.Background(), tokenoutgoing.ExchangeRequest{
		TokenEndPoint: server.URL,
		PeerDomain:    "nextcloud.example.com",
		SharedSecret:  "test-secret",
	})

	if err != nil {
		t.Fatalf("Exchange failed: %v", err)
	}
	if result.AccessToken != "nc-compat-token" {
		t.Errorf("expected 'nc-compat-token', got %s", result.AccessToken)
	}
}

func TestClient_Exchange_StrictProfile_AuthorizationCode(t *testing.T) {
	// Strict profile (no TokenExchangeGrantType override) defaults to authorization_code.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("failed to parse form: %v", err)
		}
		got := r.FormValue("grant_type")
		if got != "authorization_code" {
			t.Errorf("grant_type = %q, want %q", got, "authorization_code")
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(token.TokenResponse{
			AccessToken: "strict-ac-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	}))
	defer server.Close()

	httpClient := httpclient.NewContextClient(httpclient.New(&config.OutboundHTTPConfig{
		SSRFMode: "off",
	}, nil))

	// Strict mode with profile registry but peer not mapped -> falls back to strict profile
	mappings := []peercompat.ProfileMapping{}
	profileRegistry := peercompat.NewProfileRegistry(nil, mappings)

	client := tokenoutgoing.NewClient(
		httpClient,
		&mockSigner{},
		makePolicy("strict", profileRegistry),
		"my-instance.example.com",
	)

	result, err := client.Exchange(context.Background(), tokenoutgoing.ExchangeRequest{
		TokenEndPoint: server.URL,
		PeerDomain:    "peer.example.com",
		SharedSecret:  "test-secret",
	})

	if err != nil {
		t.Fatalf("Exchange failed: %v", err)
	}
	if result.AccessToken != "strict-ac-token" {
		t.Errorf("expected 'strict-ac-token', got %s", result.AccessToken)
	}
}

// isClassifiedError checks if err is a ClassifiedError and populates ce.
func isClassifiedError(err error, ce **peercompat.ClassifiedError) bool {
	if e, ok := err.(*peercompat.ClassifiedError); ok {
		*ce = e
		return true
	}
	return false
}
