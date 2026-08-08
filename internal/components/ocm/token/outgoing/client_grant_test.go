// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package outgoing_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/reason"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token"
	tokenoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token/outgoing"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
)

func TestClient_Exchange_OAuthError(t *testing.T) {
	server := newTokenTestServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		tshttp.MustEncodeJSON(t, w, token.OAuthError{
			Error:            token.ErrorInvalidGrant,
			ErrorDescription: "invalid code",
		})
	}))
	defer server.Close()

	httpClient := httpclient.NewContextClient(httpclient.New(&config.OutboundHTTPConfig{
		SSRF: config.SSRFConfig{Mode: "off"},
	}, nil))

	client := tokenoutgoing.NewClient(httpClient, &mockSigner{}, "local.example.com")

	_, err := client.Exchange(context.Background(), tokenoutgoing.ExchangeRequest{
		TokenEndPoint: server.URL,
		SharedSecret:  "bad-secret",
	}, httpSigDiscovery())
	if err == nil {
		t.Fatal("expected error for invalid grant")
	}

	var ce *reason.ClassifiedError
	if !isClassifiedError(err, &ce) {
		t.Errorf("expected ClassifiedError, got %T", err)
	}
}

func TestClient_Exchange_DefaultGrantType_AuthorizationCode(t *testing.T) {
	server := newTokenTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("failed to parse form: %v", err)
		}

		got := r.FormValue("grant_type")
		if got != "authorization_code" {
			t.Errorf("grant_type = %q, want %q", got, "authorization_code")
		}

		w.Header().Set("Content-Type", "application/json")
		tshttp.MustEncodeJSON(t, w, token.TokenResponse{
			AccessToken: "ac-token",
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
		t.Fatalf("Exchange failed: %v", err)
	}

	if result.AccessToken != "ac-token" {
		t.Errorf("expected 'ac-token', got %s", result.AccessToken)
	}
}

// isClassifiedError reports whether err is a ClassifiedError and populates ce.
func isClassifiedError(err error, ce **reason.ClassifiedError) bool {
	e := &reason.ClassifiedError{}
	if errors.As(err, &e) {
		*ce = e

		return true
	}

	return false
}
