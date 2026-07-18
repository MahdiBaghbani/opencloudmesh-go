// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package outgoing_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peercompat"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/reason"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token"
	tokenoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token/outgoing"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
)

func TestClient_Exchange_OAuthError(t *testing.T) {
	server := newDiscoveryAwareTokenServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(token.OAuthError{
			Error:            token.ErrorInvalidGrant,
			ErrorDescription: "invalid code",
		})
	}))
	defer server.Close()

	httpClient := httpclient.NewContextClient(httpclient.New(&config.OutboundHTTPConfig{
		SSRF: config.SSRFConfig{Mode: "off"},
	}, nil))

	client := tokenoutgoing.NewClient(
		httpClient,
		dummyDiscClient(),
		&mockSigner{},
		makePolicy("strict", nil),
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

	var ce *reason.ClassifiedError
	if !isClassifiedError(err, &ce) {
		t.Errorf("expected ClassifiedError, got %T", err)
	}
}

func TestClient_Exchange_DefaultGrantType_AuthorizationCode(t *testing.T) {
	server := newDiscoveryAwareTokenServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		SSRF: config.SSRFConfig{Mode: "off"},
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
		t.Fatalf("Exchange failed: %v", err)
	}
	if result.AccessToken != "ac-token" {
		t.Errorf("expected 'ac-token', got %s", result.AccessToken)
	}
}

func TestClient_Exchange_StrictProfile_AuthorizationCode(t *testing.T) {
	server := newDiscoveryAwareTokenServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		SSRF: config.SSRFConfig{Mode: "off"},
	}, nil))

	mappings := []peercompat.ProfileMapping{}
	profileRegistry := peercompat.NewProfileRegistry(nil, mappings)

	client := tokenoutgoing.NewClient(
		httpClient,
		dummyDiscClient(),
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

// isClassifiedError reports whether err is a ClassifiedError and populates ce.
func isClassifiedError(err error, ce **reason.ClassifiedError) bool {
	if e, ok := err.(*reason.ClassifiedError); ok {
		*ce = e
		return true
	}
	return false
}
