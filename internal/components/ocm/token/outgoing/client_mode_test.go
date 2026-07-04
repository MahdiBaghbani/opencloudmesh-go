// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package outgoing_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peercompat"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token"
	tokenoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token/outgoing"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
)

func TestClient_Exchange_OutboundModeOff(t *testing.T) {
	server := newDiscoveryAwareTokenServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Signature") == "" {
			t.Error("expected Signature header even when outbound_mode=off")
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(token.TokenResponse{
			AccessToken: "signed-off-mode-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	}))
	defer server.Close()

	httpClient := httpclient.NewContextClient(httpclient.New(&config.OutboundHTTPConfig{
		DerivedSSRFMode: "off",
	}, nil))

	client := tokenoutgoing.NewClient(
		httpClient,
		dummyDiscClient(),
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
	if result.AccessToken != "signed-off-mode-token" {
		t.Errorf("expected 'signed-off-mode-token', got %s", result.AccessToken)
	}
}

func TestClient_Exchange_OutboundModeOff_NoSignerRejected(t *testing.T) {
	httpClient := httpclient.NewContextClient(httpclient.New(&config.OutboundHTTPConfig{
		DerivedSSRFMode: "off",
	}, nil))

	client := tokenoutgoing.NewClient(
		httpClient,
		dummyDiscClient(),
		nil,
		makePolicy("off", nil),
		"my-instance.example.com",
	)

	_, err := client.Exchange(context.Background(), tokenoutgoing.ExchangeRequest{
		TokenEndPoint: "https://peer.example.com/token",
		PeerDomain:    "peer.example.com",
		SharedSecret:  "test-secret",
	})
	if err == nil {
		t.Fatal("expected error when token exchange has no signer")
	}
}

func TestClient_Exchange_StrictModeWithSigner(t *testing.T) {
	server := newDiscoveryAwareTokenServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		DerivedSSRFMode: "off",
	}, nil))

	client := tokenoutgoing.NewClient(
		httpClient,
		dummyDiscClient(),
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
	server := newDiscoveryAwareTokenServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		DerivedSSRFMode: "off",
	}, nil))

	client := tokenoutgoing.NewClient(
		httpClient,
		dummyDiscClient(),
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
	server := newDiscoveryAwareTokenServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		DerivedSSRFMode: "off",
	}, nil))

	client := tokenoutgoing.NewClient(
		httpClient,
		dummyDiscClient(),
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

func TestClient_Exchange_PeerProfileQuirkStillSigns(t *testing.T) {
	server := newDiscoveryAwareTokenServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Signature") == "" {
			t.Error("expected signed token exchange even when accept_plain_token quirk exists")
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(token.TokenResponse{
			AccessToken: "signed-quirk-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	}))
	defer server.Close()

	httpClient := httpclient.NewContextClient(httpclient.New(&config.OutboundHTTPConfig{
		DerivedSSRFMode: "off",
	}, nil))

	mappings := []peercompat.ProfileMapping{
		{Pattern: "nextcloud.example.com", Profile: "nextcloud"},
	}
	profileRegistry := peercompat.NewProfileRegistry(nil, mappings)

	client := tokenoutgoing.NewClient(
		httpClient,
		dummyDiscClient(),
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
		t.Fatalf("Exchange should succeed with signature: %v", err)
	}
	if result.AccessToken != "signed-quirk-token" {
		t.Errorf("expected 'signed-quirk-token', got %s", result.AccessToken)
	}
}
