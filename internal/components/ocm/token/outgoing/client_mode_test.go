// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package outgoing_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token"
	tokenoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token/outgoing"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
)

func TestClient_Exchange_NoSignerRejected(t *testing.T) {
	httpClient := httpclient.NewContextClient(httpclient.New(&config.OutboundHTTPConfig{
		SSRF: config.SSRFConfig{Mode: "off"},
	}, nil))

	client := tokenoutgoing.NewClient(httpClient, nil, "local.example.com")

	_, err := client.Exchange(context.Background(), tokenoutgoing.ExchangeRequest{
		TokenEndPoint: "https://peer.example.com/token",
		SharedSecret:  "test-secret",
	}, httpSigDiscovery())
	if err == nil {
		t.Fatal("expected error when token exchange has no signer for http-sig peer")
	}
}

func TestClient_Exchange_WithSigner(t *testing.T) {
	server := newTokenTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Signature") == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(token.OAuthError{ //nolint:errcheck // test mock handler: JSON encode
				Error:            token.ErrorUnauthorized,
				ErrorDescription: "signature required",
			})

			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(token.TokenResponse{ //nolint:errcheck // test mock handler: JSON encode
			AccessToken: "signed-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	}))
	defer server.Close()

	httpClient := httpclient.NewContextClient(httpclient.New(&config.OutboundHTTPConfig{
		SSRF: config.SSRFConfig{Mode: "off"},
	}, nil))

	client := tokenoutgoing.NewClient(httpClient, &mockSigner{}, "local.example.com")

	result, err := client.Exchange(context.Background(), tokenoutgoing.ExchangeRequest{
		TokenEndPoint: server.URL,
		SharedSecret:  "test-secret",
	}, httpSigDiscovery())
	if err != nil {
		t.Fatalf("Exchange should succeed with signature: %v", err)
	}

	if result.AccessToken != "signed-token" {
		t.Errorf("expected 'signed-token', got %s", result.AccessToken)
	}
}

func TestClient_Exchange_SignsWhenReceiverAdvertisesHTTPSig(t *testing.T) { //nolint:dupl // intentional: parallel signed/unsigned exchange tests share client setup but assert different signature behavior
	server := newTokenTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Signature") == "" {
			t.Error("expected signed token exchange")
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(token.TokenResponse{ //nolint:errcheck // test mock handler: JSON encode
			AccessToken: "signed-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	}))
	defer server.Close()

	httpClient := httpclient.NewContextClient(httpclient.New(&config.OutboundHTTPConfig{
		SSRF: config.SSRFConfig{Mode: "off"},
	}, nil))

	client := tokenoutgoing.NewClient(httpClient, &mockSigner{}, "local.example.com")

	result, err := client.Exchange(context.Background(), tokenoutgoing.ExchangeRequest{
		TokenEndPoint: server.URL,
		SharedSecret:  "test-secret",
	}, httpSigDiscovery())
	if err != nil {
		t.Fatalf("Exchange should succeed with signature: %v", err)
	}

	if result.AccessToken != "signed-token" {
		t.Errorf("expected 'signed-token', got %s", result.AccessToken)
	}
}
