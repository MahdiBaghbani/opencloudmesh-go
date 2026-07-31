// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package outgoing_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/reason"
	tokenoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token/outgoing"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
)

// unsignedMockSigner satisfies RequestSigner without adding a Signature header.
// It is used to exercise the unsigned 401 fail-closed path.
type unsignedMockSigner struct{}

func (s *unsignedMockSigner) Sign(_ *http.Request) error {
	return nil
}

func TestClient_Exchange_Unsigned401FailClosed(t *testing.T) {
	var hits atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)

		if r.Header.Get("Signature") != "" {
			t.Error("expected unsigned request")
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		tshttp.MustWrite(t, w, []byte(`{"error":"invalid_client","error_description":"client authentication failed"}`))
	}))
	defer server.Close()

	httpClient := httpclient.NewContextClient(httpclient.New(&config.OutboundHTTPConfig{
		SSRF: config.SSRFConfig{Mode: "off"},
	}, nil))
	client := tokenoutgoing.NewClient(httpClient, &unsignedMockSigner{}, "my-instance.example.com")

	_, err := client.Exchange(context.Background(), tokenoutgoing.ExchangeRequest{
		TokenEndPoint: server.URL,
		SharedSecret:  "test-secret",
	}, noHTTPSigDiscovery())
	if err == nil {
		t.Fatal("expected failure for unsigned 401")
	}

	if hits.Load() != 1 {
		t.Fatalf("hits = %d, want 1 (no retry)", hits.Load())
	}

	var ce *reason.ClassifiedError
	if !isClassifiedError(err, &ce) {
		t.Fatalf("expected ClassifiedError, got %T", err)
	}

	if ce.ReasonCode != reason.ReasonTokenUnauthorized {
		t.Fatalf("expected reason %q, got %q", reason.ReasonTokenUnauthorized, ce.ReasonCode)
	}
}

func TestClient_Exchange_Signed401FailClosed(t *testing.T) {
	var hits atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)

		if r.Header.Get("Signature") == "" {
			t.Error("expected signed request")
		}

		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	httpClient := httpclient.NewContextClient(httpclient.New(&config.OutboundHTTPConfig{
		SSRF: config.SSRFConfig{Mode: "off"},
	}, nil))
	client := tokenoutgoing.NewClient(httpClient, &mockSigner{}, "my-instance.example.com")

	_, err := client.Exchange(context.Background(), tokenoutgoing.ExchangeRequest{
		TokenEndPoint: server.URL,
		SharedSecret:  "test-secret",
	}, httpSigDiscovery())
	if err == nil {
		t.Fatal("expected failure for signed 401")
	}

	if hits.Load() != 1 {
		t.Fatalf("hits = %d, want 1 (no retry)", hits.Load())
	}

	var ce *reason.ClassifiedError
	if !isClassifiedError(err, &ce) {
		t.Fatalf("expected ClassifiedError, got %T", err)
	}

	if ce.ReasonCode != reason.ReasonSignatureRequired {
		t.Fatalf("expected reason %q, got %q", reason.ReasonSignatureRequired, ce.ReasonCode)
	}
}

func TestClient_Exchange_403FailClosed(t *testing.T) {
	var hits atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		tshttp.MustWrite(t, w, []byte(`{"error":"access_denied","error_description":"token exchange denied"}`))
	}))
	defer server.Close()

	httpClient := httpclient.NewContextClient(httpclient.New(&config.OutboundHTTPConfig{
		SSRF: config.SSRFConfig{Mode: "off"},
	}, nil))
	client := tokenoutgoing.NewClient(httpClient, &mockSigner{}, "my-instance.example.com")

	_, err := client.Exchange(context.Background(), tokenoutgoing.ExchangeRequest{
		TokenEndPoint: server.URL,
		SharedSecret:  "test-secret",
	}, httpSigDiscovery())
	if err == nil {
		t.Fatal("expected failure for 403")
	}

	if hits.Load() != 1 {
		t.Fatalf("hits = %d, want 1 (no retry)", hits.Load())
	}

	var ce *reason.ClassifiedError
	if !isClassifiedError(err, &ce) {
		t.Fatalf("expected ClassifiedError, got %T", err)
	}

	if ce.ReasonCode != reason.ReasonTokenForbidden {
		t.Fatalf("expected reason %q, got %q", reason.ReasonTokenForbidden, ce.ReasonCode)
	}
}
