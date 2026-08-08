// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

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

// TestClient_ExplicitProxySuccess verifies that an explicit proxy_url routes
// requests through the configured proxy rather than directly to the destination,
// and that the proxy receives an absolute-form request URI as required by
// RFC 7230 s5.3.2 for HTTP proxy requests.
func TestClient_ExplicitProxySuccess(t *testing.T) {
	var (
		proxyHit                                         atomic.Bool
		observedRequestURI, observedMethod, observedHost atomic.Value
	)

	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyHit.Store(true)
		observedRequestURI.Store(r.RequestURI)
		observedMethod.Store(r.Method)
		observedHost.Store(r.Host)
		w.WriteHeader(http.StatusOK)

		if _, err := w.Write([]byte("via-proxy")); err != nil {
			t.Errorf("write response: %v", err)
		}
	}))
	defer proxy.Close()

	cfg := outboundtestutil.PermissiveConfig()
	cfg.ProxyURL = proxy.URL
	c := httpclient.New(cfg, nil)

	const destURL = "http://external.example.invalid/api"

	resp, err := c.Get(context.Background(), destURL) //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	if err != nil {
		t.Fatalf("expected success through proxy, got: %v", err)
	}
	defer outboundtestutil.MustClose(t, resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	if !proxyHit.Load() {
		t.Error("request did not route through the configured proxy")
	}
	// HTTP proxying must send the full destination URL as the request target
	// (absolute-form), not just the path.
	if got, ok := observedRequestURI.Load().(string); !ok || got != destURL {
		t.Errorf("proxy saw request URI %q, want %q (absolute-form)", got, destURL)
	}

	if got, ok := observedMethod.Load().(string); !ok || got != http.MethodGet {
		t.Errorf("proxy saw method %q, want GET", got)
	}

	if got, ok := observedHost.Load().(string); !ok || got != "external.example.invalid" {
		t.Errorf("proxy saw Host header %q, want %q", got, "external.example.invalid")
	}
}

// TestClient_DestinationPrivateIPBlockedWithProxy verifies that the preflight
// SSRF check still blocks private-IP destinations even when a proxy is configured.
func TestClient_DestinationPrivateIPBlockedWithProxy(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Preflight must fire before the proxy is ever contacted.
		t.Error("proxy should not have been reached for a blocked destination")
		w.WriteHeader(http.StatusOK)
	}))
	defer proxy.Close()

	cfg := outboundtestutil.StrictNoneOutboundConfig()
	cfg.ProxyURL = proxy.URL
	c := httpclient.New(cfg, nil)

	privateTargets := []string{
		"http://192.168.1.1/resource",
		"http://10.0.0.1/resource",
		"http://127.0.0.1/resource",
	}

	for _, target := range privateTargets {
		resp, err := c.Get(context.Background(), target) //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
		if resp != nil {
			outboundtestutil.MustClose(t, resp.Body)
		}

		if err == nil {
			t.Errorf("expected SSRF error for %s even with proxy configured", target)

			continue
		}

		if !httpclient.IsSSRFError(err) {
			t.Errorf("expected SSRF error for %s, got: %v", target, err)
		}
	}
}

// TestClient_PrivateProxyAllowedInStrictMode verifies that the configured
// proxy host is operator-trusted: a loopback/private proxy endpoint is allowed
// in strict mode. Destination SSRF is still enforced by the preflight check,
// so private-IP destinations are blocked before the proxy is contacted.
func TestClient_PrivateProxyAllowedInStrictMode(t *testing.T) {
	var proxyHit atomic.Bool

	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxyHit.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer proxy.Close()

	cfg := outboundtestutil.StrictNoneOutboundConfig()
	cfg.ProxyURL = proxy.URL
	c := httpclient.New(cfg, nil)

	// 203.0.113.10 is TEST-NET-3, not blocked by preflight SSRF (not
	// private/loopback by Go's net.IP classification). The proxy lives on
	// loopback but is operator-trusted, so it must be reached and respond.
	resp, err := c.Get(context.Background(), "http://203.0.113.10/resource") //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	if err != nil {
		t.Fatalf("expected success through private proxy in strict mode, got: %v", err)
	}
	defer outboundtestutil.MustClose(t, resp.Body)

	if !proxyHit.Load() {
		t.Fatal("private proxy host must be reachable in strict mode (operator-trusted)")
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}
