// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package discovery_test

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

func tlsTestClient() *httpclient.Client {
	cfg := tshttp.PermissiveConfig()
	cfg.InsecureSkipVerify = true

	return httpclient.New(cfg, nil)
}

func TestClientFetchFresh_BypassesCacheAndCapturesMetadata(t *testing.T) {
	t.Parallel()

	var fetchCount atomic.Int32

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/ocm" {
			http.NotFound(w, r)

			return
		}

		fetchCount.Add(1)
		w.Header().Set("X-Nextcloud-WELL-KNOWN", "1")

		raw := validDiscoveryPayload(serverURLFromRequest(r), map[string]any{
			"provider": "Nextcloud 28",
		})

		w.Header().Set("Content-Type", "application/json")
		tshttp.MustEncodeJSON(t, w, raw)
	}))
	t.Cleanup(server.Close)

	c := cache.NewDefault()
	client := discovery.NewClient(tlsTestClient(), c)

	ctx := context.Background()
	baseURL := server.URL

	if _, err := client.Discover(ctx, baseURL); err != nil {
		t.Fatalf("Discover seed cache: %v", err)
	}

	result, err := client.FetchFresh(ctx, baseURL)
	if err != nil {
		t.Fatalf("FetchFresh: %v", err)
	}

	if fetchCount.Load() != 2 {
		t.Fatalf("fetch count = %d, want 2 (cache seed + fresh bypass)", fetchCount.Load())
	}

	if result.Discovery == nil || result.Discovery.Provider != "Nextcloud 28" {
		t.Fatalf("discovery provider = %v", result.Discovery)
	}

	if result.Headers.Get("X-Nextcloud-WELL-KNOWN") != "1" {
		t.Fatal("expected copied response headers")
	}

	if result.TLS == nil {
		t.Fatal("expected TLS state")
	}

	if result.ServerIP == "" {
		t.Fatal("expected connected server IP")
	}

	if len(result.Raw) == 0 {
		t.Fatal("expected raw discovery bytes")
	}
}

func TestClientFetchFresh_HTTPErrorRetainsTLSState(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/ocm" {
			http.NotFound(w, r)

			return
		}

		http.Error(w, "bad gateway", http.StatusBadGateway)
	}))
	t.Cleanup(server.Close)

	client := discovery.NewClient(tlsTestClient(), cache.NewDefault())

	result, err := client.FetchFresh(context.Background(), server.URL)
	if err == nil {
		t.Fatal("expected fetch error for non-200")
	}

	if result == nil {
		t.Fatal("expected partial fetch result")
	}

	if result.TLS == nil {
		t.Fatal("expected TLS state after HTTPS error response")
	}
}

func TestClientFetchFresh_PreservesFetchError(t *testing.T) {
	t.Parallel()

	client := discovery.NewClient(tlsTestClient(), cache.NewDefault())

	result, err := client.FetchFresh(context.Background(), "http://127.0.0.1:1")
	if err == nil {
		t.Fatal("expected fetch error")
	}

	if result == nil {
		t.Fatal("expected partial fetch result")
	}

	if result.FetchErr == nil {
		t.Fatal("expected fetch error retained on result")
	}
}

func TestClientFetchFresh_HTTPErrorRetainsFetchErr(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/ocm" {
			http.NotFound(w, r)

			return
		}

		http.Error(w, "bad gateway", http.StatusBadGateway)
	}))
	t.Cleanup(server.Close)

	client := discovery.NewClient(tlsTestClient(), cache.NewDefault())

	result, err := client.FetchFresh(context.Background(), server.URL)
	if err == nil {
		t.Fatal("expected fetch error for non-200")
	}

	if result == nil || result.FetchErr == nil {
		t.Fatal("expected fetch error retained on partial result")
	}
}

func TestClientDiscover_RemainsBackwardCompatible(t *testing.T) {
	t.Parallel()

	server := newDiscoveryTestServer(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/ocm" {
			http.NotFound(w, r)

			return
		}

		raw := validDiscoveryPayload(serverURL, map[string]any{"provider": "nextcloud"})

		w.Header().Set("Content-Type", "application/json")
		tshttp.MustEncodeJSON(t, w, raw)
	})

	client := discovery.NewClient(tlsTestClient(), cache.NewDefault())

	disc, err := client.Discover(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	if disc.Provider != "nextcloud" {
		t.Fatalf("provider = %q", disc.Provider)
	}
}

func serverURLFromRequest(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}

	return scheme + "://" + r.Host
}

func TestFetchResult_TLSIsCopiedState(t *testing.T) {
	t.Parallel()

	var captured *tls.ConnectionState

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/ocm" {
			http.NotFound(w, r)

			return
		}

		raw := validDiscoveryPayload(serverURLFromRequest(r), nil)

		w.Header().Set("Content-Type", "application/json")
		tshttp.MustEncodeJSON(t, w, raw)
	}))
	t.Cleanup(server.Close)

	client := discovery.NewClient(tlsTestClient(), cache.NewDefault())

	result, err := client.FetchFresh(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("FetchFresh: %v", err)
	}

	captured = result.TLS
	if captured == nil {
		t.Fatal("expected TLS state")
	}

	if tls.CipherSuiteName(captured.CipherSuite) == "" {
		t.Fatal("expected cipher suite label")
	}
}
