package client_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	outboundtestutil "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
)

// TestClient_ProxyEnvFallbackDisabled_IgnoresEnv verifies that when
// ProxyEnvFallback is false the client ignores HTTP_PROXY/HTTPS_PROXY and
// connects directly to the destination.
func TestClient_ProxyEnvFallbackDisabled_IgnoresEnv(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://proxy.invalid:8080")
	t.Setenv("HTTPS_PROXY", "http://proxy.invalid:8080")
	t.Setenv("http_proxy", "http://proxy.invalid:8080")
	t.Setenv("https_proxy", "http://proxy.invalid:8080")
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
	t.Setenv("ALL_PROXY", "")
	t.Setenv("all_proxy", "")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("direct"))
	}))
	defer server.Close()

	cfg := outboundtestutil.PermissiveConfig()
	cfg.ProxyEnvFallback = false // ignore env proxy
	c := httpclient.New(cfg, nil)

	// proxy.invalid is unreachable; direct path must succeed.
	resp, err := c.Get(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("expected direct connection, got error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

// TestClient_ProxyEnvFallbackEnabled_UsesEnv verifies that when ProxyEnvFallback
// is true the client routes requests through the proxy advertised in HTTP_PROXY.
func TestClient_ProxyEnvFallbackEnabled_UsesEnv(t *testing.T) {
	var proxyHit atomic.Bool

	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyHit.Store(true)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("via-env-proxy"))
	}))
	defer proxy.Close()

	// Set env proxy before constructing the client so proxy detection runs.
	// Clear all other proxy-related vars so ambient env does not interfere.
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("http_proxy", proxy.URL)
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("https_proxy", "")
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
	t.Setenv("ALL_PROXY", "")
	t.Setenv("all_proxy", "")

	cfg := outboundtestutil.PermissiveConfig()
	cfg.ProxyEnvFallback = true
	c := httpclient.New(cfg, nil)

	resp, err := c.Get(context.Background(), "http://external.example.invalid/api")
	if err != nil {
		t.Fatalf("expected success through env proxy, got: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if !proxyHit.Load() {
		t.Error("request did not route through the env proxy")
	}
}

// TestClient_ExplicitProxyOverridesEnv verifies that an explicit cfg.ProxyURL
// wins over the HTTP_PROXY env var even when ProxyEnvFallback is true.
func TestClient_ExplicitProxyOverridesEnv(t *testing.T) {
	var explicitHit, envHit atomic.Bool

	explicitProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		explicitHit.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer explicitProxy.Close()

	envProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		envHit.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer envProxy.Close()

	t.Setenv("HTTP_PROXY", envProxy.URL)
	t.Setenv("HTTPS_PROXY", envProxy.URL)
	t.Setenv("http_proxy", envProxy.URL)
	t.Setenv("https_proxy", envProxy.URL)
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
	t.Setenv("ALL_PROXY", "")
	t.Setenv("all_proxy", "")

	cfg := outboundtestutil.PermissiveConfig()
	cfg.ProxyURL = explicitProxy.URL // explicit wins
	cfg.ProxyEnvFallback = true      // even when env fallback is enabled
	c := httpclient.New(cfg, nil)

	resp, err := c.Get(context.Background(), "http://external.example.invalid/api")
	if err != nil {
		t.Fatalf("expected success through explicit proxy, got: %v", err)
	}
	defer resp.Body.Close()

	if !explicitHit.Load() {
		t.Error("request must route through the explicit proxy_url")
	}
	if envHit.Load() {
		t.Error("env proxy must not be contacted when explicit proxy_url is set")
	}
}
