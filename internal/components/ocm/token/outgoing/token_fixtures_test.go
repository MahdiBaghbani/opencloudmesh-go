// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package outgoing_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/reason"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token"
	tokenoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token/outgoing"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
)

// mockSigner adds a Signature header for tests.
type mockSigner struct {
	failSign bool
}

func (s *mockSigner) Sign(req *http.Request) error {
	if s.failSign {
		return &reason.ClassifiedError{
			ReasonCode: reason.ReasonSignatureInvalid,
			Message:    "signing failed",
		}
	}

	req.Header.Set("Signature", "mock-signature")

	return nil
}

// httpSigDiscovery returns a discovery document that advertises the http-sig
// capability.
func httpSigDiscovery() *spec.Discovery {
	return &spec.Discovery{
		Capabilities: []string{spec.CapabilityHTTPSig},
	}
}

// noHTTPSigDiscovery returns a discovery document that does not advertise
// http-sig.
func noHTTPSigDiscovery() *spec.Discovery {
	return &spec.Discovery{}
}

func newTokenTestServer(tokenHandler http.HandlerFunc) *httptest.Server {
	return httptest.NewServer(tokenHandler)
}

// runExchangeSignatureCase drives one signed/unsigned token exchange case: the
// test server asserts the Signature header presence and returns wantToken, and
// the test asserts the client returns it.
func runExchangeSignatureCase(
	t *testing.T,
	expectSigned bool,
	localInstance string,
	discovery *spec.Discovery,
	wantToken string,
) {
	t.Helper()

	server := newTokenTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if expectSigned && r.Header.Get("Signature") == "" {
			t.Error("expected signed token exchange")
		}

		if !expectSigned && r.Header.Get("Signature") != "" {
			t.Error("expected unsigned request for peer without http-sig")
		}

		w.Header().Set("Content-Type", "application/json")
		tshttp.MustEncodeJSON(t, w, token.TokenResponse{
			AccessToken: wantToken,
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	}))
	defer server.Close()

	httpClient := httpclient.NewContextClient(httpclient.New(&config.OutboundHTTPConfig{
		SSRF: config.SSRFConfig{Mode: "off"},
	}, nil))

	client := tokenoutgoing.NewClient(httpClient, &mockSigner{}, localInstance)

	result, err := client.Exchange(context.Background(), tokenoutgoing.ExchangeRequest{
		TokenEndPoint: server.URL,
		SharedSecret:  "test-secret",
	}, discovery)
	if err != nil {
		t.Fatalf("Exchange failed: %v", err)
	}

	if result.AccessToken != wantToken {
		t.Errorf("expected access_token %q, got %s", wantToken, result.AccessToken)
	}
}
