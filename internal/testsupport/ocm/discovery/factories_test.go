// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package discovery_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
	tsdiscovery "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/ocm/discovery"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

func TestNewTestClient_returnsNonNilClient(t *testing.T) {
	client := tsdiscovery.NewTestClient(t)
	if client == nil {
		t.Fatal("NewTestClient returned nil")
	}
}

func TestNewTestClient_WithCache(t *testing.T) {
	t.Run("default uses real cache", func(t *testing.T) {
		client := tsdiscovery.NewTestClient(t)
		if client.IsNoopCache() {
			t.Fatal("expected default cache, got NoopCache")
		}
	})

	t.Run("WithCache wires NoopCache", func(t *testing.T) {
		client := tsdiscovery.NewTestClient(t, tsdiscovery.WithCache(cache.NewNoopCache()))
		if !client.IsNoopCache() {
			t.Fatal("expected NoopCache when WithCache is set")
		}
	})
}

func TestNewTestClient_WithHTTPClient(t *testing.T) {
	const pem = "-----BEGIN PUBLIC KEY-----\ntest-body\n-----END PUBLIC KEY-----"

	doc := tsdiscovery.InlineKeyDiscoveryDoc(t, pem)
	srv, _ := tsdiscovery.NewDiscoveryTestServer(t, doc)
	baseURL := strings.TrimSuffix(srv.URL, "/")

	t.Run("default permissive client discovers", func(t *testing.T) {
		client := tsdiscovery.NewTestClient(t)
		if _, err := client.Discover(context.Background(), baseURL); err != nil {
			t.Fatalf("Discover() error = %v, want nil", err)
		}
	})

	t.Run("strict client blocks httptest host", func(t *testing.T) {
		strictClient := httpclient.New(tshttp.StrictNoneOutboundConfig(), nil)
		client := tsdiscovery.NewTestClient(t, tsdiscovery.WithHTTPClient(strictClient))

		_, err := client.Discover(context.Background(), baseURL)
		if err == nil {
			t.Fatal("Discover() error = nil, want SSRF or outbound failure")
		}

		if !errors.Is(err, httpclient.ErrSSRFBlocked) {
			t.Fatalf("Discover() error = %v, want ErrSSRFBlocked", err)
		}
	})
}

func TestInlineKeyDiscoveryDoc_singularPublicKeyPEM(t *testing.T) {
	const (
		pem       = "-----BEGIN PUBLIC KEY-----\ntest-body\n-----END PUBLIC KEY-----"
		wantKeyID = "https://peer.example.com/ocm#test-key"
	)

	doc := tsdiscovery.InlineKeyDiscoveryDoc(t, pem)

	if got, ok := doc["enabled"].(bool); !ok || !got {
		t.Fatalf("enabled = %v, want true", doc["enabled"])
	}

	if got := doc["apiVersion"]; got != spec.APIVersionPin {
		t.Fatalf("apiVersion = %v, want %q", got, spec.APIVersionPin)
	}

	pk, ok := doc["publicKey"].(map[string]string)
	if !ok {
		t.Fatalf("publicKey type = %T, want map[string]string", doc["publicKey"])
	}

	if got := pk["keyId"]; got != wantKeyID {
		t.Fatalf("keyId = %q, want %q", got, wantKeyID)
	}

	if got := pk["publicKeyPem"]; got != pem {
		t.Fatalf("publicKeyPem = %q, want %q", got, pem)
	}

	caps, ok := doc["capabilities"].([]string)
	if !ok {
		t.Fatalf("capabilities type = %T, want []string", doc["capabilities"])
	}

	if len(caps) != 1 || caps[0] != "http-sig" {
		t.Fatalf("capabilities = %v, want [http-sig]", caps)
	}
}

func TestNewDiscoveryTestServer_servesDynamicEndpoint(t *testing.T) {
	const pem = "-----BEGIN PUBLIC KEY-----\ntest-body\n-----END PUBLIC KEY-----"

	doc := tsdiscovery.InlineKeyDiscoveryDoc(t, pem)
	srv, _ := tsdiscovery.NewDiscoveryTestServer(t, doc)

	resp, err := http.Get(srv.URL + "/.well-known/ocm")
	if err != nil {
		t.Fatalf("GET discovery: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	var served map[string]any
	if err := json.Unmarshal(body, &served); err != nil {
		t.Fatalf("unmarshal served doc: %v", err)
	}

	wantEndpoint := strings.TrimSuffix(srv.URL, "/") + "/ocm"
	if got := served["endPoint"]; got != wantEndpoint {
		t.Fatalf("endPoint = %q, want %q", got, wantEndpoint)
	}

	if got, ok := served["enabled"].(bool); !ok || !got {
		t.Fatalf("enabled = %v, want true", served["enabled"])
	}

	if got := served["apiVersion"]; got != spec.APIVersionPin {
		t.Fatalf("apiVersion = %v, want %q", got, spec.APIVersionPin)
	}

	pk, ok := served["publicKey"].(map[string]any)
	if !ok {
		t.Fatalf("publicKey type = %T, want map[string]any", served["publicKey"])
	}

	if got := pk["keyId"]; got != "https://peer.example.com/ocm#test-key" {
		t.Fatalf("keyId = %v, want %q", got, "https://peer.example.com/ocm#test-key")
	}

	if got := pk["publicKeyPem"]; got != pem {
		t.Fatalf("publicKeyPem = %v, want %q", got, pem)
	}

	caps, ok := served["capabilities"].([]any)
	if !ok {
		t.Fatalf("capabilities type = %T, want []any", served["capabilities"])
	}

	if len(caps) != 1 {
		t.Fatalf("capabilities len = %d, want 1", len(caps))
	}

	if got, ok := caps[0].(string); !ok || got != "http-sig" {
		t.Fatalf("capabilities[0] = %v, want %q", caps[0], "http-sig")
	}

	if got := doc["endPoint"]; got == wantEndpoint {
		t.Fatalf("InlineKeyDiscoveryDoc map was mutated: endPoint = %q", got)
	}
}
