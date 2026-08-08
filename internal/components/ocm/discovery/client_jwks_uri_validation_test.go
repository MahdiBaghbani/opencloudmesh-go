// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package discovery_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
)

func TestClientDiscover_AcceptsCustomJwksUri(t *testing.T) {
	t.Parallel()
	server := newDiscoveryTestServer(t, func(serverURL string, w http.ResponseWriter, _ *http.Request) {
		raw := validDiscoveryPayload(serverURL, map[string]any{
			"capabilities": []string{"http-sig"},
			"jwksUri":      strings.TrimSuffix(serverURL, "/") + "/custom/jwks",
		})

		w.Header().Set("Content-Type", "application/json")
		tshttp.MustEncodeJSON(t, w, raw)
	})

	client := discovery.NewClient(httpclient.New(tshttp.PermissiveConfig(), nil), nil)

	disc, err := client.Discover(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Discover failed for custom jwksUri: %v", err)
	}

	want := strings.TrimSuffix(server.URL, "/") + "/custom/jwks"
	if disc.JwksUri != want {
		t.Errorf("JwksUri = %q, want %q", disc.JwksUri, want)
	}
}

func TestClientDiscover_RejectsRelativeJwksUri(t *testing.T) {
	t.Parallel()
	server := newDiscoveryTestServer(t, func(serverURL string, w http.ResponseWriter, _ *http.Request) {
		raw := validDiscoveryPayload(serverURL, map[string]any{
			"capabilities": []string{"http-sig"},
			"jwksUri":      "/.well-known/jwks.json",
		})

		w.Header().Set("Content-Type", "application/json")
		tshttp.MustEncodeJSON(t, w, raw)
	})

	client := discovery.NewClient(httpclient.New(tshttp.PermissiveConfig(), nil), nil)

	_, err := client.Discover(context.Background(), server.URL)
	if err == nil {
		t.Fatal("expected error for relative jwksUri")
	}

	if !errors.Is(err, discovery.ErrInvalidDiscoveryJSON) {
		t.Fatalf("errors.Is(err, ErrInvalidDiscoveryJSON) = false, err = %v", err)
	}
}

func TestClientDiscover_RejectsCrossAuthorityJwksUri(t *testing.T) {
	t.Parallel()

	const crossAuthorityURI = "https://other.example.com/jwks"

	server := newDiscoveryTestServer(t, func(serverURL string, w http.ResponseWriter, _ *http.Request) {
		raw := validDiscoveryPayload(serverURL, map[string]any{
			"capabilities": []string{"http-sig"},
			"jwksUri":      crossAuthorityURI,
		})

		w.Header().Set("Content-Type", "application/json")
		tshttp.MustEncodeJSON(t, w, raw)
	})

	client := discovery.NewClient(httpclient.New(tshttp.PermissiveConfig(), nil), nil)

	_, err := client.Discover(context.Background(), server.URL)
	if err == nil {
		t.Fatal("expected error for cross-authority jwksUri")
	}

	if !errors.Is(err, discovery.ErrInvalidDiscoveryJSON) {
		t.Fatalf("errors.Is(err, ErrInvalidDiscoveryJSON) = false, err = %v", err)
	}

	msg := err.Error()
	if strings.Contains(msg, crossAuthorityURI) {
		t.Fatalf("Discover error = %q, must not echo cross-authority jwksUri", msg)
	}
}

func TestClientDiscover_RejectsJwksUriWithCredentials(t *testing.T) {
	t.Parallel()
	server := newDiscoveryTestServer(t, func(serverURL string, w http.ResponseWriter, _ *http.Request) {
		raw := validDiscoveryPayload(serverURL, map[string]any{
			"capabilities": []string{"http-sig"},
			"jwksUri":      strings.Replace(serverURL, "://", "://user:pass@", 1) + "/jwks",
		})

		w.Header().Set("Content-Type", "application/json")
		tshttp.MustEncodeJSON(t, w, raw)
	})

	client := discovery.NewClient(httpclient.New(tshttp.PermissiveConfig(), nil), nil)

	_, err := client.Discover(context.Background(), server.URL)
	if err == nil {
		t.Fatal("expected error for credential-bearing jwksUri")
	}

	if !errors.Is(err, discovery.ErrInvalidDiscoveryJSON) {
		t.Fatalf("errors.Is(err, ErrInvalidDiscoveryJSON) = false, err = %v", err)
	}

	msg := err.Error()
	if strings.Contains(msg, "user:pass") || strings.Contains(msg, "user@") {
		t.Fatalf("Discover error = %q, must not echo credential userinfo", msg)
	}
}

func TestClientDiscover_RejectsJwksUriWithFragment(t *testing.T) {
	t.Parallel()

	var jwksURI string

	server := newDiscoveryTestServer(t, func(serverURL string, w http.ResponseWriter, _ *http.Request) {
		jwksURI = strings.TrimSuffix(serverURL, "/") + "/jwks#key-1"
		raw := validDiscoveryPayload(serverURL, map[string]any{
			"capabilities": []string{"http-sig"},
			"jwksUri":      jwksURI,
		})

		w.Header().Set("Content-Type", "application/json")
		tshttp.MustEncodeJSON(t, w, raw)
	})

	client := discovery.NewClient(httpclient.New(tshttp.PermissiveConfig(), nil), nil)

	_, err := client.Discover(context.Background(), server.URL)
	if err == nil {
		t.Fatal("expected error for fragment-bearing jwksUri")
	}

	if !errors.Is(err, discovery.ErrInvalidDiscoveryJSON) {
		t.Fatalf("errors.Is(err, ErrInvalidDiscoveryJSON) = false, err = %v", err)
	}

	msg := err.Error()
	if jwksURI != "" && strings.Contains(msg, jwksURI) {
		t.Fatalf("Discover error = %q, must not echo fragment-bearing jwksUri", msg)
	}
}

func TestClientDiscover_JwksUriSurvivesCacheRoundTrip(t *testing.T) {
	t.Parallel()

	var fetchCount int

	server := newDiscoveryTestServer(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/ocm" {
			http.NotFound(w, r)

			return
		}

		fetchCount++
		raw := validDiscoveryPayload(serverURL, map[string]any{
			"capabilities": []string{"http-sig"},
			"jwksUri":      strings.TrimSuffix(serverURL, "/") + "/jwks",
		})

		w.Header().Set("Content-Type", "application/json")
		tshttp.MustEncodeJSON(t, w, raw)
	})

	client := discovery.NewClient(httpclient.New(tshttp.PermissiveConfig(), nil), nil)

	want := strings.TrimSuffix(server.URL, "/") + "/jwks"

	disc, err := client.Discover(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("first Discover failed: %v", err)
	}

	if disc.JwksUri != want {
		t.Fatalf("JwksUri = %q, want %q", disc.JwksUri, want)
	}

	cached, err := client.Discover(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("second Discover failed on cache read: %v", err)
	}

	if fetchCount != 1 {
		t.Fatalf("fetchCount = %d, want 1 after bounded cache hit", fetchCount)
	}

	if cached.JwksUri != want {
		t.Errorf("cached JwksUri = %q, want %q", cached.JwksUri, want)
	}
}
