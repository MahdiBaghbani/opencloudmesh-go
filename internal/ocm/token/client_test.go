// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package token_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/federation"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/httpclient"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/ocm/token"
)

// mockSigner is a test signer that adds a mock signature header.
type mockSigner struct {
	failSign bool
}

func (s *mockSigner) Sign(req *http.Request) error {
	if s.failSign {
		return &federation.ClassifiedError{
			ReasonCode: federation.ReasonSignatureInvalid,
			Message:    "signing failed",
		}
	}
	req.Header.Set("Signature", "mock-signature")
	return nil
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
	}))

	client := token.NewClient(
		httpClient,
		&mockSigner{},
		"strict",
		nil,
		"my-instance.example.com",
	)

	result, err := client.Exchange(context.Background(), token.ExchangeRequest{
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

func TestClient_Exchange_SignatureModeOff(t *testing.T) {
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
	}))

	// Mode "off" should skip signing
	client := token.NewClient(
		httpClient,
		&mockSigner{},
		"off",
		nil,
		"my-instance.example.com",
	)

	result, err := client.Exchange(context.Background(), token.ExchangeRequest{
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

func TestClient_Exchange_StrictModeRejectsUnsigned(t *testing.T) {
	// Create mock server that rejects unsigned requests
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
	}))

	// Strict mode with working signer should succeed
	client := token.NewClient(
		httpClient,
		&mockSigner{},
		"strict",
		nil,
		"my-instance.example.com",
	)

	result, err := client.Exchange(context.Background(), token.ExchangeRequest{
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

func TestClient_Exchange_LenientModeWithQuirk(t *testing.T) {
	callCount := 0

	// Create mock server that rejects signed requests but accepts unsigned
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++

		if r.Header.Get("Signature") != "" {
			// Reject signed request
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(token.OAuthError{
				Error:            token.ErrorUnauthorized,
				ErrorDescription: "signature not supported",
			})
			return
		}

		// Accept unsigned request
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
	}))

	// Set up profile registry with nextcloud profile (has accept_plain_token quirk)
	mappings := []federation.ProfileMapping{
		{Pattern: "nextcloud.example.com", ProfileName: "nextcloud"},
	}
	profileRegistry := federation.NewProfileRegistry(nil, mappings)

	client := token.NewClient(
		httpClient,
		&mockSigner{},
		"lenient",
		profileRegistry,
		"my-instance.example.com",
	)

	result, err := client.Exchange(context.Background(), token.ExchangeRequest{
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
	if result.QuirkApplied != "accept_plain_token" {
		t.Errorf("expected quirk 'accept_plain_token', got %s", result.QuirkApplied)
	}
	if callCount < 2 {
		t.Errorf("expected at least 2 calls (strict then quirk), got %d", callCount)
	}
}

func TestClient_Exchange_LenientModeNoQuirkWithoutProfile(t *testing.T) {
	// Create mock server that always rejects
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(token.OAuthError{
			Error:            token.ErrorUnauthorized,
			ErrorDescription: "signature required",
		})
	}))
	defer server.Close()

	httpClient := httpclient.NewContextClient(httpclient.New(&config.OutboundHTTPConfig{
		SSRFMode: "off",
	}))

	// No profile mapping -> uses strict profile which has no quirks
	profileRegistry := federation.NewProfileRegistry(nil, nil)

	client := token.NewClient(
		httpClient,
		&mockSigner{},
		"lenient",
		profileRegistry,
		"my-instance.example.com",
	)

	_, err := client.Exchange(context.Background(), token.ExchangeRequest{
		TokenEndPoint: server.URL,
		PeerDomain:    "unknown.example.com", // No profile match
		SharedSecret:  "test-secret",
	})

	if err == nil {
		t.Fatal("expected error when no quirk available")
	}
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
	}))

	client := token.NewClient(
		httpClient,
		nil,
		"off",
		nil,
		"my-instance.example.com",
	)

	_, err := client.Exchange(context.Background(), token.ExchangeRequest{
		TokenEndPoint: server.URL,
		PeerDomain:    "peer.example.com",
		SharedSecret:  "bad-secret",
	})

	if err == nil {
		t.Fatal("expected error for invalid grant")
	}

	// Check it's properly classified
	var ce *federation.ClassifiedError
	if !isClassifiedError(err, &ce) {
		t.Errorf("expected ClassifiedError, got %T", err)
	}
}

// isClassifiedError checks if err is a ClassifiedError and populates ce.
func isClassifiedError(err error, ce **federation.ClassifiedError) bool {
	if e, ok := err.(*federation.ClassifiedError); ok {
		*ce = e
		return true
	}
	return false
}
