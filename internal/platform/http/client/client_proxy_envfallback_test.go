// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package client_test

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	outboundtestutil "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
)

// TestClient_UseEnvFallbackDisabled_IgnoresEnv verifies that when
// use_env_fallback (UseEnvFallback) is false the client ignores
// HTTP_PROXY/HTTPS_PROXY and connects directly to the destination.
//
// The destination must run on a non-loopback IP. Go's httpproxy unconditionally
// bypasses proxies for loopback destinations (127.x and ::1) regardless of env
// configuration, so a loopback destination would let a regression that always
// honors the env proxy pass this test: the proxy would be bypassed either way.
// A non-loopback destination plus a hit-counting proxy server makes the
// invariant observable: with use_env_fallback=false the proxy must never be
// contacted, and the request must reach the destination directly.
func TestClient_UseEnvFallbackDisabled_IgnoresEnv(t *testing.T) {
	localIP := findNonLoopbackIPv4()
	if localIP == nil {
		t.Skip("no non-loopback IPv4 interface available; skipping env-fallback disabled test")
	}

	var proxyHit atomic.Bool

	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyHit.Store(true)
		t.Errorf("proxy must not be contacted when use_env_fallback is false: got %s %s",
			r.Method, r.RequestURI)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer proxy.Close()

	// Destination server on a non-loopback IP so Go's httpproxy does not
	// special-case it independently of use_env_fallback.
	destListener, err := net.Listen("tcp", localIP.String()+":0")
	if err != nil {
		t.Fatalf("listen on non-loopback IP %s: %v", localIP, err)
	}

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("direct")) //nolint:errcheck // test handler response write
	}))
	server.Listener = destListener

	server.Start()
	defer server.Close()

	// Clear REQUEST_METHOD so httpproxy.FromEnvironment does not see a CGI
	// environment; otherwise an ambient value could mask the env-proxy path
	// and let the test pass for the wrong reason.
	t.Setenv("REQUEST_METHOD", "")
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("http_proxy", proxy.URL)
	t.Setenv("https_proxy", proxy.URL)
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
	t.Setenv("ALL_PROXY", "")
	t.Setenv("all_proxy", "")

	cfg := outboundtestutil.PermissiveConfig()
	cfg.UseEnvFallback = false // ignore env proxy
	c := httpclient.New(cfg, nil)

	resp, err := c.Get(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("expected direct connection, got error: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck // test response body close

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	if proxyHit.Load() {
		t.Error("env proxy must not be contacted when use_env_fallback is false")
	}
}

// TestClient_UseEnvFallbackEnabled_UsesEnv verifies that when
// use_env_fallback (UseEnvFallback) is true the client routes requests
// through the proxy advertised in HTTP_PROXY.
func TestClient_UseEnvFallbackEnabled_UsesEnv(t *testing.T) {
	var proxyHit atomic.Bool

	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxyHit.Store(true)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("via-env-proxy")) //nolint:errcheck // test handler response write
	}))
	defer proxy.Close()

	// Set env proxy before constructing the client so proxy detection runs.
	// Clear all other proxy-related vars so ambient env does not interfere.
	// REQUEST_METHOD is cleared so httpproxy.FromEnvironment does not treat
	// this as a CGI environment and silently disable the env proxy.
	t.Setenv("REQUEST_METHOD", "")
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("http_proxy", proxy.URL)
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("https_proxy", "")
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
	t.Setenv("ALL_PROXY", "")
	t.Setenv("all_proxy", "")

	cfg := outboundtestutil.PermissiveConfig()
	cfg.UseEnvFallback = true
	c := httpclient.New(cfg, nil)

	resp, err := c.Get(context.Background(), "http://external.example.invalid/api")
	if err != nil {
		t.Fatalf("expected success through env proxy, got: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck // test response body close

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	if !proxyHit.Load() {
		t.Error("request did not route through the env proxy")
	}
}

// TestClient_ExplicitProxyOverridesEnv verifies that an explicit cfg.ProxyURL
// wins over the HTTP_PROXY env var even when use_env_fallback is true.
func TestClient_ExplicitProxyOverridesEnv(t *testing.T) {
	var explicitHit, envHit atomic.Bool

	explicitProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		explicitHit.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer explicitProxy.Close()

	envProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		envHit.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer envProxy.Close()

	t.Setenv("REQUEST_METHOD", "")
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
	cfg.UseEnvFallback = true        // even when env fallback is enabled
	c := httpclient.New(cfg, nil)

	resp, err := c.Get(context.Background(), "http://external.example.invalid/api")
	if err != nil {
		t.Fatalf("expected success through explicit proxy, got: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck // test response body close

	if !explicitHit.Load() {
		t.Error("request must route through the explicit proxy_url")
	}

	if envHit.Load() {
		t.Error("env proxy must not be contacted when explicit proxy_url is set")
	}
}
