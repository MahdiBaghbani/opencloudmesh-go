package client_test

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client/outboundtestutil"
)

func TestClient_SSRFProtection(t *testing.T) {
	client := outboundtestutil.NewStrictNone(nil)

	tests := []struct {
		name      string
		url       string
		wantError bool
	}{
		{
			name:      "localhost blocked",
			url:       "http://localhost/test",
			wantError: true,
		},
		{
			name:      "127.0.0.1 blocked",
			url:       "http://127.0.0.1/test",
			wantError: true,
		},
		{
			name:      "loopback IPv6 blocked",
			url:       "http://[::1]/test",
			wantError: true,
		},
		{
			name:      "private 192.168 blocked",
			url:       "http://192.168.1.1/test",
			wantError: true,
		},
		{
			name:      "private 10.x blocked",
			url:       "http://10.0.0.1/test",
			wantError: true,
		},
		{
			name:      "private 172.16 blocked",
			url:       "http://172.16.0.1/test",
			wantError: true,
		},
		{
			name:      "link-local blocked",
			url:       "http://169.254.1.1/test",
			wantError: true,
		},
	}

	ctx := context.Background()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := client.Get(ctx, tt.url)

			if tt.wantError {
				if err == nil {
					t.Errorf("expected SSRF error, got nil")
				} else if !httpclient.IsSSRFError(err) {
					t.Errorf("expected SSRF-classified error, got: %v", err)
				}
			} else {
				if httpclient.IsSSRFError(err) {
					t.Errorf("unexpected SSRF error: %v", err)
				}
			}
		})
	}
}

func TestClient_SSRFOff(t *testing.T) {
	cfg := outboundtestutil.StrictNoneOutboundConfig()
	cfg.SSRF.Mode = "off"
	client := httpclient.New(cfg, nil)

	ctx := context.Background()

	// With SSRF off, localhost should not be blocked at the SSRF check level
	// (it will still fail to connect if nothing is listening)
	_, err := client.Get(ctx, "http://localhost:99999/test")

	// Should not be an SSRF error
	if httpclient.IsSSRFError(err) {
		t.Errorf("unexpected SSRF error when mode is off: %v", err)
	}
}

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

	// Set env proxy before constructing the client so the hostname snapshot fires.
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

// TestClient_NOProxy_DirectPathSSRFStillBlocks verifies that NO_PROXY changing
// routing to direct never bypasses strict-mode SSRF destination checks.
// The client still uses env fallback, but private/loopback targets are blocked
// by the preflight check in DoWithOptions before any dial or proxy decision.
func TestClient_NOProxy_DirectPathSSRFStillBlocks(t *testing.T) {
	var proxyHit atomic.Bool

	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyHit.Store(true)
		t.Error("proxy must not be reached for SSRF-blocked destinations")
		w.WriteHeader(http.StatusOK)
	}))
	defer proxy.Close()

	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("http_proxy", proxy.URL)
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("https_proxy", "")
	t.Setenv("ALL_PROXY", "")
	t.Setenv("all_proxy", "")
	// NO_PROXY directs these addresses to bypass the proxy and go direct.
	// SSRF must still block them regardless.
	t.Setenv("NO_PROXY", "192.168.1.1,10.0.0.1,127.0.0.1")
	t.Setenv("no_proxy", "192.168.1.1,10.0.0.1,127.0.0.1")

	cfg := outboundtestutil.StrictNoneOutboundConfig()
	cfg.ProxyEnvFallback = true
	c := httpclient.New(cfg, nil)

	privateTargets := []string{
		"http://192.168.1.1/resource",
		"http://10.0.0.1/resource",
		"http://127.0.0.1/resource",
	}

	for _, target := range privateTargets {
		t.Run(target, func(t *testing.T) {
			_, err := c.Get(context.Background(), target)
			if err == nil {
				t.Errorf("expected SSRF error for %s even with NO_PROXY bypass", target)
				return
			}
			if !httpclient.IsSSRFError(err) {
				t.Errorf("expected SSRF error for %s, got: %v", target, err)
			}
		})
	}

	if proxyHit.Load() {
		t.Error("proxy must not be hit; preflight SSRF check must fire first")
	}
}

// findNonLoopbackIPv4 returns the first non-loopback, non-link-local IPv4
// address that can be listened on, or nil if none is available. It is used
// by TestClient_NOProxy_RoutingBypass to obtain a destination IP that Go's
// env-driven proxy logic does not special-case the way it does for loopback.
func findNonLoopbackIPv4() net.IP {
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.To4() == nil {
				continue
			}
			// Confirm we can actually bind a listener on this address.
			if l, err := net.Listen("tcp", ip.String()+":0"); err == nil {
				l.Close()
				return ip.To4()
			}
		}
	}
	return nil
}

// TestClient_NOProxy_RoutingBypass verifies that when NO_PROXY matches the
// destination host the client bypasses the env proxy and connects directly.
// This is the routing complement to TestClient_NOProxy_DirectPathSSRFStillBlocks,
// which covers the security invariant: strict-mode SSRF blocking is not weakened
// by a NO_PROXY-driven direct path.
//
// Design note: the destination must run on a non-loopback address.
// Go's env-driven proxy logic unconditionally skips proxies for loopback IPs
// (127.x and ::1) regardless of NO_PROXY, so using httptest.NewServer (which
// always binds to 127.0.0.1) would conflate Go's built-in loopback bypass with
// the NO_PROXY bypass and prove nothing about NO_PROXY routing. A non-loopback
// local IP ensures that without NO_PROXY the proxy would be contacted, and
// with NO_PROXY matching the IP it is not.
func TestClient_NOProxy_RoutingBypass(t *testing.T) {
	localIP := findNonLoopbackIPv4()
	if localIP == nil {
		t.Skip("no non-loopback IPv4 interface available; skipping NO_PROXY routing test")
	}

	var proxyHit atomic.Bool

	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyHit.Store(true)
		t.Errorf("proxy must not be contacted when NO_PROXY matches destination: got %s %s",
			r.Method, r.RequestURI)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer proxy.Close()

	// Destination server on a non-loopback IP so Go does not special-case it
	// independently of NO_PROXY.
	destListener, err := net.Listen("tcp", localIP.String()+":0")
	if err != nil {
		t.Fatalf("listen on non-loopback IP %s: %v", localIP, err)
	}
	destSrv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("direct"))
	}))
	destSrv.Listener = destListener
	destSrv.Start()
	defer destSrv.Close()

	destURL := destSrv.URL + "/resource"
	destHost := localIP.String()

	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("http_proxy", proxy.URL)
	t.Setenv("NO_PROXY", destHost)
	t.Setenv("no_proxy", destHost)
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("https_proxy", "")
	t.Setenv("ALL_PROXY", "")
	t.Setenv("all_proxy", "")

	// SSRF off: destination is a local non-loopback IP used for the routing test.
	cfg := outboundtestutil.PermissiveConfig()
	cfg.ProxyEnvFallback = true
	// Construct after setting env so proxy host snapshotting matches the env
	// proxy configuration used by the transport.
	c := httpclient.New(cfg, nil)

	resp, err := c.Get(context.Background(), destURL)
	if err != nil {
		t.Fatalf("expected direct connection via NO_PROXY bypass, got error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if proxyHit.Load() {
		t.Error("proxy was contacted despite NO_PROXY matching the destination IP")
	}
}

func TestClient_SignedRequestsRejectRedirects(t *testing.T) {
	// Create a server that redirects
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/target", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := outboundtestutil.NewPermissive(nil)

	// Signed request should fail on redirect
	req, _ := http.NewRequest("GET", server.URL+"/redirect", nil)
	_, err := client.DoSigned(req)

	if err == nil {
		t.Fatal("expected error for signed request with redirect")
	}
	if !httpclient.IsRedirectError(err) {
		t.Errorf("expected redirect error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "signed requests cannot follow redirects") {
		t.Errorf("expected 'signed requests cannot follow redirects' in error, got: %v", err)
	}
}

func TestClient_UnsignedFollowsOneRedirect(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/target", http.StatusFound)
			return
		}
		if r.URL.Path == "/target" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("reached target"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := outboundtestutil.NewPermissive(nil)

	resp, err := client.Get(context.Background(), server.URL+"/start")
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if requestCount != 2 {
		t.Errorf("expected 2 requests (original + redirect), got %d", requestCount)
	}
}

func TestClient_UnsignedRejectsTooManyRedirects(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always redirect
		http.Redirect(w, r, r.URL.Path+"x", http.StatusFound)
	}))
	defer server.Close()

	client := outboundtestutil.NewPermissive(nil) // MaxRedirects=1 by default

	_, err := client.Get(context.Background(), server.URL+"/start")
	if err == nil {
		t.Fatal("expected error for too many redirects")
	}
	if !strings.Contains(err.Error(), "too many redirects") {
		t.Errorf("expected 'too many redirects' in error, got: %v", err)
	}
}

func TestClient_UnsignedRejectsCrossHostRedirect(t *testing.T) {
	// First server redirects to second server (different host)
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer targetServer.Close()

	redirectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, targetServer.URL+"/target", http.StatusFound)
	}))
	defer redirectServer.Close()

	client := outboundtestutil.NewPermissive(nil)

	_, err := client.Get(context.Background(), redirectServer.URL+"/start")
	if err == nil {
		t.Fatal("expected error for cross-host redirect")
	}
	if !strings.Contains(err.Error(), "different host") {
		t.Errorf("expected 'different host' in error, got: %v", err)
	}
}

func TestClient_UnsignedRejectsHTTPSDowngrade(t *testing.T) {
	// HTTP target the redirect will point to. The downgrade check fires before
	// the same-host check, so the target host does not matter for this test.
	httpTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer httpTarget.Close()

	// HTTPS source that redirects down to plain HTTP.
	tlsSource := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, httpTarget.URL+"/target", http.StatusFound)
	}))
	defer tlsSource.Close()

	// Trust the TLS source's self-signed certificate.
	serverCert := tlsSource.TLS.Certificates[0]
	x509Cert, err := x509.ParseCertificate(serverCert.Certificate[0])
	if err != nil {
		t.Fatalf("parse TLS cert: %v", err)
	}
	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(x509Cert)

	c := outboundtestutil.NewPermissive(rootCAs)

	_, err = c.Get(context.Background(), tlsSource.URL)
	if err == nil {
		t.Fatal("expected error for HTTPS->HTTP redirect downgrade")
	}
	if !httpclient.IsRedirectError(err) {
		t.Errorf("expected redirect error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "redirect from https to http blocked") {
		t.Errorf("expected downgrade error message, got: %v", err)
	}
}

func TestClient_IPv6BracketHandling(t *testing.T) {
	client := outboundtestutil.NewStrictNone(nil)

	// Test that IPv6 with brackets is properly parsed and blocked
	tests := []struct {
		name string
		url  string
	}{
		{"IPv6 loopback with brackets", "http://[::1]/test"},
		{"IPv6 loopback with port", "http://[::1]:8080/test"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := client.Get(context.Background(), tt.url)
			if err == nil {
				t.Error("expected SSRF error for loopback IPv6")
			}
			if !httpclient.IsSSRFError(err) {
				t.Errorf("expected SSRF error, got: %v", err)
			}
		})
	}
}

func TestClient_UnresolvableHostBlocked(t *testing.T) {
	client := outboundtestutil.NewStrictNone(nil)

	// Use a domain that definitely doesn't exist
	_, err := client.Get(context.Background(), "http://this-domain-does-not-exist-12345.invalid/test")
	if err == nil {
		t.Fatal("expected error for unresolvable host")
	}
	// The .invalid TLD is guaranteed to fail resolution (RFC 6761); the client
	// must classify this as an SSRF error (ErrHostUnresolvable), not let it
	// pass silently as a generic connection error.
	if !httpclient.IsSSRFError(err) {
		t.Errorf("expected SSRF-classified error for unresolvable host, got: %v", err)
	}
}

// TestIsAllowedIP exercises the isAllowedIP predicate via client behavior:
// public IPs pass the strict-mode SSRF preflight check (error is a connection
// failure, not SSRF), while private/loopback/link-local/multicast IPs are
// blocked with an SSRF-classified error.
func TestIsAllowedIP(t *testing.T) {
	cfg := outboundtestutil.StrictNoneOutboundConfig()
	cfg.TimeoutMS = 500
	cfg.ConnectTimeoutMS = 200
	c := httpclient.New(cfg, nil)
	ctx := context.Background()

	tests := []struct {
		name        string
		url         string
		wantBlocked bool
	}{
		{"public 1.2.3.4 not blocked", "http://1.2.3.4/", false},
		{"public 8.8.8.8 not blocked", "http://8.8.8.8/", false},
		{"loopback 127.0.0.1 blocked", "http://127.0.0.1/", true},
		{"IPv6 loopback blocked", "http://[::1]/", true},
		{"private 10.x blocked", "http://10.0.0.1/", true},
		{"private 192.168 blocked", "http://192.168.1.1/", true},
		{"private 172.16 blocked", "http://172.16.0.1/", true},
		{"link-local blocked", "http://169.254.1.1/", true},
		{"unspecified 0.0.0.0 blocked", "http://0.0.0.0/", true},
		{"multicast blocked", "http://224.0.0.1/", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := c.Get(ctx, tt.url)
			if tt.wantBlocked {
				if !httpclient.IsSSRFError(err) {
					t.Errorf("expected SSRF-blocked error for %s, got: %v", tt.url, err)
				}
			} else {
				if httpclient.IsSSRFError(err) {
					t.Errorf("expected no SSRF error for public IP %s, got: %v", tt.url, err)
				}
			}
		})
	}
}

func TestClient_DoPreservesInterface(t *testing.T) {
	// Verify Do() still works with the standard http.Request interface
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := outboundtestutil.NewPermissive(nil)

	req, _ := http.NewRequest("GET", server.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do() failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestSSRFBlocksLocalhostWithPort(t *testing.T) {
	// Regression test: localhost:8080 must be blocked as localhost (not unresolvable)
	client := outboundtestutil.NewStrictNone(nil)

	tests := []struct {
		name string
		url  string
	}{
		{"localhost:8080", "http://localhost:8080/test"},
		{"localhost:9000", "http://localhost:9000/test"},
		{"127.0.0.1:8080", "http://127.0.0.1:8080/test"},
		{"[::1]:8080", "http://[::1]:8080/test"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := client.Get(context.Background(), tt.url)
			if err == nil {
				t.Errorf("expected SSRF error for %s", tt.name)
				return
			}
			if !httpclient.IsSSRFError(err) {
				t.Errorf("expected SSRF error, got: %v", err)
			}
			// Ensure the error mentions "localhost" or "blocked", not "unresolvable"
			if strings.Contains(err.Error(), "could not be resolved") {
				t.Errorf("localhost should be blocked as localhost, not as unresolvable: %v", err)
			}
		})
	}
}

func TestSignedNoRedirectViaHeaders(t *testing.T) {
	// Requests with RFC 9421 signature headers must not follow redirects
	// even when using the unsigned Do() path
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/target", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := outboundtestutil.NewPermissive(nil)

	tests := []struct {
		name   string
		header string
	}{
		{"Signature header", "Signature"},
		{"Signature-Input header", "Signature-Input"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", server.URL+"/redirect", nil)
			req.Header.Set(tt.header, "sig=()")

			// Use Do() not DoSigned() - central header detection should still catch it
			_, err := client.Do(req)
			if err == nil {
				t.Fatal("expected error for signed request with redirect")
			}
			if !httpclient.IsRedirectError(err) {
				t.Errorf("expected redirect error, got: %v", err)
			}
			if !strings.Contains(err.Error(), "signed requests cannot follow redirects") {
				t.Errorf("expected 'signed requests cannot follow redirects', got: %v", err)
			}
		})
	}
}

// blockingResolver simulates a DNS resolver that blocks until context is canceled.
type blockingResolver struct {
	unblockCh chan struct{}
}

func (r *blockingResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-r.unblockCh:
		return []net.IPAddr{{IP: net.ParseIP("1.2.3.4")}}, nil
	}
}

func TestContextAwareDNSCancellation(t *testing.T) {
	cfg := outboundtestutil.StrictNoneOutboundConfig()
	cfg.TimeoutMS = 10000 // long timeout so context cancellation fires first
	cfg.ConnectTimeoutMS = 5000
	client := httpclient.New(cfg, nil)

	// Install a blocking resolver
	resolver := &blockingResolver{unblockCh: make(chan struct{})}
	client.SetResolver(resolver)

	// Create a context with a short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := client.Get(ctx, "http://example.com/test")
	elapsed := time.Since(start)

	// Should return quickly (around 100ms), not hang
	if elapsed > 500*time.Millisecond {
		t.Errorf("DNS cancellation took too long: %v (expected ~100ms)", elapsed)
	}

	// Should have an error (context deadline exceeded or canceled)
	if err == nil {
		t.Fatal("expected error when context is canceled")
	}
}

func TestRedirectSameHostSemantics(t *testing.T) {
	// Test same-host redirect checks use relative URLs so the server host is preserved
	// This tests that relative redirects work correctly and that port normalization applies
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if r.URL.Path == "/start" {
			// Relative redirect - same host by definition
			http.Redirect(w, r, "/target", http.StatusFound)
			return
		}
		if r.URL.Path == "/target" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("reached"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := outboundtestutil.NewPermissive(nil)

	// Test relative redirect (always same-host)
	resp, err := client.Get(context.Background(), server.URL+"/start")
	if err != nil {
		t.Fatalf("relative redirect should work: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if requestCount != 2 {
		t.Errorf("expected 2 requests (start + redirect), got %d", requestCount)
	}
}

func TestRedirectCrossHostBlocked(t *testing.T) {
	// Test that redirects to a different host are blocked
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer targetServer.Close()

	redirectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Redirect to different host (target server)
		http.Redirect(w, r, targetServer.URL+"/target", http.StatusFound)
	}))
	defer redirectServer.Close()

	client := outboundtestutil.NewPermissive(nil)

	_, err := client.Get(context.Background(), redirectServer.URL+"/start")
	if err == nil {
		t.Fatal("cross-host redirect should be blocked")
	}
	if !strings.Contains(err.Error(), "different host") {
		t.Errorf("expected 'different host' error, got: %v", err)
	}
}

func TestIsSameHostPortNormalization(t *testing.T) {
	// Test port normalization logic via a test where we inject port in redirect
	// This simulates: server at :PORT redirects to same host with explicit :PORT
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			// Build absolute URL with explicit port (should still be same-host)
			targetURL := "http://" + r.Host + "/target"
			http.Redirect(w, r, targetURL, http.StatusFound)
			return
		}
		if r.URL.Path == "/target" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := outboundtestutil.NewPermissive(nil)

	resp, err := client.Get(context.Background(), server.URL+"/start")
	if err != nil {
		t.Fatalf("same-host redirect with explicit port should work: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

// TestClient_ExplicitProxySuccess verifies that an explicit proxy_url routes
// requests through the configured proxy rather than directly to the destination,
// and that the proxy receives an absolute-form request URI as required by
// RFC 7230 s5.3.2 for HTTP proxy requests.
func TestClient_ExplicitProxySuccess(t *testing.T) {
	var proxyHit atomic.Bool
	var observedRequestURI, observedMethod, observedHost atomic.Value

	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyHit.Store(true)
		observedRequestURI.Store(r.RequestURI)
		observedMethod.Store(r.Method)
		observedHost.Store(r.Host)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("via-proxy"))
	}))
	defer proxy.Close()

	cfg := outboundtestutil.PermissiveConfig()
	cfg.ProxyURL = proxy.URL
	c := httpclient.New(cfg, nil)

	const destURL = "http://external.example.invalid/api"
	resp, err := c.Get(context.Background(), destURL)
	if err != nil {
		t.Fatalf("expected success through proxy, got: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if !proxyHit.Load() {
		t.Error("request did not route through the configured proxy")
	}
	// HTTP proxying must send the full destination URL as the request target
	// (absolute-form), not just the path.
	if got, _ := observedRequestURI.Load().(string); got != destURL {
		t.Errorf("proxy saw request URI %q, want %q (absolute-form)", got, destURL)
	}
	if got, _ := observedMethod.Load().(string); got != http.MethodGet {
		t.Errorf("proxy saw method %q, want GET", got)
	}
	if got, _ := observedHost.Load().(string); got != "external.example.invalid" {
		t.Errorf("proxy saw Host header %q, want %q", got, "external.example.invalid")
	}
}

// TestClient_DestinationPrivateIPBlockedWithProxy verifies that the preflight
// SSRF check still blocks private-IP destinations even when a proxy is configured.
func TestClient_DestinationPrivateIPBlockedWithProxy(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		_, err := c.Get(context.Background(), target)
		if err == nil {
			t.Errorf("expected SSRF error for %s even with proxy configured", target)
			continue
		}
		if !httpclient.IsSSRFError(err) {
			t.Errorf("expected SSRF error for %s, got: %v", target, err)
		}
	}
}

// TestClient_SignedRedirectRejectedWithProxy verifies that signed-request
// redirect rejection is enforced even when an explicit proxy is configured
// and the proxy itself responds with a redirect.
func TestClient_SignedRedirectRejectedWithProxy(t *testing.T) {
	// Proxy responds with a redirect to prove rejection happens at the client,
	// not at the transport level.
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://other.example.invalid/target", http.StatusFound)
	}))
	defer proxy.Close()

	cfg := outboundtestutil.PermissiveConfig()
	cfg.ProxyURL = proxy.URL
	c := httpclient.New(cfg, nil)

	req, _ := http.NewRequest("GET", "http://external.example.invalid/resource", nil)
	_, err := c.DoSigned(req)

	if err == nil {
		t.Fatal("expected error for signed request receiving redirect via proxy")
	}
	if !httpclient.IsRedirectError(err) {
		t.Errorf("expected redirect error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "signed requests cannot follow redirects") {
		t.Errorf("expected 'signed requests cannot follow redirects', got: %v", err)
	}
}

// TestClient_PrivateProxyAllowedInStrictMode verifies that the configured
// proxy host is operator-trusted: a loopback/private proxy endpoint is allowed
// in strict mode. Destination SSRF is still enforced by the preflight check,
// so private-IP destinations are blocked before the proxy is contacted.
func TestClient_PrivateProxyAllowedInStrictMode(t *testing.T) {
	var proxyHit atomic.Bool
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	resp, err := c.Get(context.Background(), "http://203.0.113.10/resource")
	if err != nil {
		t.Fatalf("expected success through private proxy in strict mode, got: %v", err)
	}
	defer resp.Body.Close()

	if !proxyHit.Load() {
		t.Fatal("private proxy host must be reachable in strict mode (operator-trusted)")
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

// TestClient_HTTPSProxyCONNECT verifies that HTTPS destinations are tunneled
// through the configured proxy using HTTP CONNECT (RFC 7231 s4.3.6), and that
// the proxy observes a correct CONNECT host:port request before the TLS
// handshake proceeds.
func TestClient_HTTPSProxyCONNECT(t *testing.T) {
	// HTTPS backend - the final TLS destination reached through the tunnel.
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("tls-backend-ok"))
	}))
	defer backend.Close()

	backendParsed, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("parse backend URL: %v", err)
	}
	wantCONNECTTarget := backendParsed.Host // "127.0.0.1:PORT"

	var connectSeen atomic.Bool
	var observedCONNECTTarget atomic.Value

	// Minimal CONNECT-capable proxy: records CONNECT semantics and tunnels
	// bytes to the real backend.
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			t.Errorf("proxy: expected CONNECT, got %s %s", r.Method, r.RequestURI)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		connectSeen.Store(true)
		// r.RequestURI is "host:port" for CONNECT requests.
		observedCONNECTTarget.Store(r.RequestURI)

		hijacker, ok := w.(http.Hijacker)
		if !ok {
			t.Error("proxy: hijacking not supported")
			http.Error(w, "hijacking not supported", http.StatusInternalServerError)
			return
		}

		targetConn, dialErr := net.Dial("tcp", r.Host)
		if dialErr != nil {
			http.Error(w, dialErr.Error(), http.StatusBadGateway)
			return
		}

		clientConn, _, hijackErr := hijacker.Hijack()
		if hijackErr != nil {
			targetConn.Close()
			t.Logf("proxy: hijack error: %v", hijackErr)
			return
		}

		_, _ = fmt.Fprint(clientConn, "HTTP/1.1 200 Connection established\r\n\r\n")

		// Proxy bytes bidirectionally until both sides close.
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			defer targetConn.Close()
			_, _ = io.Copy(targetConn, clientConn)
		}()
		go func() {
			defer wg.Done()
			defer clientConn.Close()
			_, _ = io.Copy(clientConn, targetConn)
		}()
		// Do not block the handler goroutine: that would cause proxy.Close()
		// (and therefore the test) to hang while the client holds the tunnel
		// open via HTTP keep-alive. Instead register a cleanup that force-
		// expires both connections so the io.Copy goroutines unblock promptly.
		t.Cleanup(func() {
			past := time.Now().Add(-time.Second)
			_ = clientConn.SetDeadline(past)
			_ = targetConn.SetDeadline(past)
			wg.Wait()
		})
	}))
	defer proxy.Close()

	// Build a cert pool trusting the backend's self-signed TLS certificate.
	serverCert := backend.TLS.Certificates[0]
	x509Cert, parseErr := x509.ParseCertificate(serverCert.Certificate[0])
	if parseErr != nil {
		t.Fatalf("parse backend TLS cert: %v", parseErr)
	}
	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(x509Cert)

	// SSRF off: backend is 127.0.0.1; SSRF bypass is intentional here because we
	// are testing CONNECT tunnel semantics, not SSRF enforcement. The companion
	// test TestClient_HTTPSPrivateDestinationBlockedWithProxy covers that
	// preflight blocks private HTTPS targets before CONNECT.
	cfg := outboundtestutil.PermissiveConfig()
	cfg.ProxyURL = proxy.URL
	c := httpclient.New(cfg, rootCAs)

	resp, err := c.Get(context.Background(), backend.URL)
	if err != nil {
		t.Fatalf("HTTPS through CONNECT proxy failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if !connectSeen.Load() {
		t.Error("proxy did not receive a CONNECT request")
	}
	if got, _ := observedCONNECTTarget.Load().(string); got != wantCONNECTTarget {
		t.Errorf("CONNECT target: got %q, want %q", got, wantCONNECTTarget)
	}
}

// TestClient_HTTPSPrivateDestinationBlockedWithProxy verifies that strict-mode
// SSRF preflight blocks private and loopback HTTPS destinations before any
// CONNECT request is sent to the proxy. This is the HTTPS counterpart to
// TestClient_DestinationPrivateIPBlockedWithProxy.
func TestClient_HTTPSPrivateDestinationBlockedWithProxy(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("proxy reached for blocked destination: %s %s", r.Method, r.RequestURI)
		w.WriteHeader(http.StatusOK)
	}))
	defer proxy.Close()

	cfg := outboundtestutil.StrictNoneOutboundConfig()
	cfg.ProxyURL = proxy.URL
	c := httpclient.New(cfg, nil)

	targets := []string{
		"https://192.168.1.1/resource",
		"https://10.0.0.1/resource",
		"https://127.0.0.1/resource",
		"https://[::1]/resource",
	}
	for _, target := range targets {
		t.Run(target, func(t *testing.T) {
			_, err := c.Get(context.Background(), target)
			if err == nil {
				t.Errorf("expected SSRF error for %s, got nil", target)
				return
			}
			if !httpclient.IsSSRFError(err) {
				t.Errorf("expected SSRF error for %s, got: %v", target, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Route policy tests
// ---------------------------------------------------------------------------

// fixedResolver maps hostnames to IP addresses for deterministic SSRF testing.
type fixedResolver struct {
	mu      sync.Mutex
	entries map[string][]net.IPAddr
}

func (r *fixedResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	addrs, ok := r.entries[host]
	if !ok {
		return nil, fmt.Errorf("no records for %s", host)
	}
	return addrs, nil
}

// corpPolicy returns a route policy allowing the given suffixes/CIDRs/ports
// for use in test configs.
func corpPolicy(suffixes, cidrs []string, ports []int) config.SSRFRoutePolicyConfig {
	return config.SSRFRoutePolicyConfig{
		AllowPrivateHostSuffixes: suffixes,
		AllowPrivateCIDRs:        cidrs,
		AllowedPorts:             ports,
	}
}

// TestRoutePolicy_PrivateHostAllowedWhenAllChecksPass verifies that a request
// reaches a private-addressed server end-to-end when all route-policy checks
// (CIDR, port, allow_ip_literals) pass. Uses a local test server so the result
// is fully deterministic and does not depend on any network dial to fail.
func TestRoutePolicy_PrivateHostAllowedWhenAllChecksPass(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	u, _ := url.Parse(server.URL)
	port, _ := strconv.Atoi(u.Port())

	cfg := outboundtestutil.StrictNoneOutboundConfig()
	cfg.TimeoutMS = 5000
	cfg.ConnectTimeoutMS = 2000
	cfg.SSRF.RoutePolicy = "corp"
	cfg.SSRF.RoutePolicies = map[string]config.SSRFRoutePolicyConfig{
		"corp": {
			AllowPrivateCIDRs: []string{"127.0.0.0/8"},
			AllowedPorts:      []int{port},
			AllowIPLiterals:   true,
		},
	}
	c := httpclient.New(cfg, nil)

	resp, err := c.Get(context.Background(), server.URL+"/api")
	if httpclient.IsSSRFError(err) {
		t.Errorf("route policy should allow this private host, got SSRF error: %v", err)
	}
	if err != nil {
		t.Fatalf("expected successful request, got: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

// TestRoutePolicy_LeadingDotSuffixNormalized verifies that suffix entries
// written with a leading dot (e.g. ".internal") are normalized before matching
// so that "service.internal" is correctly allowed.
func TestRoutePolicy_LeadingDotSuffixNormalized(t *testing.T) {
	resolver := &fixedResolver{entries: map[string][]net.IPAddr{
		"service.internal": {{IP: net.ParseIP("10.0.1.50")}},
	}}

	cfg := outboundtestutil.StrictShortTimeoutConfig()
	cfg.SSRF.RoutePolicy = "corp"
	cfg.SSRF.RoutePolicies = map[string]config.SSRFRoutePolicyConfig{
		"corp": corpPolicy(
			[]string{".internal"}, // leading dot must be stripped before match
			[]string{"10.0.0.0/8"},
			[]int{80},
		),
	}
	c := httpclient.New(cfg, nil)
	c.SetResolver(resolver)

	_, err := c.Get(context.Background(), "http://service.internal/api")
	if httpclient.IsSSRFError(err) {
		t.Errorf(".internal suffix should match service.internal after normalization, got SSRF error: %v", err)
	}
}

// TestRoutePolicy_PrivateHostDeniedWhenSuffixFails verifies that a private IP
// is blocked when the hostname does not match any allowed suffix.
func TestRoutePolicy_PrivateHostDeniedWhenSuffixFails(t *testing.T) {
	resolver := &fixedResolver{entries: map[string][]net.IPAddr{
		"other.noncorp.example": {{IP: net.ParseIP("10.0.1.50")}},
	}}

	cfg := outboundtestutil.StrictShortTimeoutConfig()
	cfg.SSRF.RoutePolicy = "corp"
	cfg.SSRF.RoutePolicies = map[string]config.SSRFRoutePolicyConfig{
		"corp": corpPolicy(
			[]string{"corp.example"}, // "noncorp.example" does not match
			[]string{"10.0.0.0/8"},
			[]int{80},
		),
	}
	c := httpclient.New(cfg, nil)
	c.SetResolver(resolver)

	_, err := c.Get(context.Background(), "http://other.noncorp.example/api")
	if !httpclient.IsSSRFError(err) {
		t.Errorf("expected SSRF error when host suffix does not match policy, got: %v", err)
	}
}

// TestRoutePolicy_PrivateHostDeniedWhenCIDRFails verifies that a private IP is
// blocked when the resolved address is not in any allowed CIDR.
func TestRoutePolicy_PrivateHostDeniedWhenCIDRFails(t *testing.T) {
	resolver := &fixedResolver{entries: map[string][]net.IPAddr{
		"internal.corp.example": {{IP: net.ParseIP("192.168.1.50")}}, // 192.168 not in 10.0.0.0/8
	}}

	cfg := outboundtestutil.StrictShortTimeoutConfig()
	cfg.SSRF.RoutePolicy = "corp"
	cfg.SSRF.RoutePolicies = map[string]config.SSRFRoutePolicyConfig{
		"corp": corpPolicy(
			[]string{"corp.example"},
			[]string{"10.0.0.0/8"}, // 192.168.1.50 not covered
			[]int{80},
		),
	}
	c := httpclient.New(cfg, nil)
	c.SetResolver(resolver)

	_, err := c.Get(context.Background(), "http://internal.corp.example/api")
	if !httpclient.IsSSRFError(err) {
		t.Errorf("expected SSRF error when resolved IP is not in allowed CIDR, got: %v", err)
	}
}

// TestRoutePolicy_PrivateHostDeniedWhenPortFails verifies that the same
// hostname is denied when the destination port is not in the allowed ports list.
func TestRoutePolicy_PrivateHostDeniedWhenPortFails(t *testing.T) {
	resolver := &fixedResolver{entries: map[string][]net.IPAddr{
		"internal.corp.example": {{IP: net.ParseIP("10.0.1.50")}},
	}}

	cfg := outboundtestutil.StrictShortTimeoutConfig()
	cfg.SSRF.RoutePolicy = "corp"
	cfg.SSRF.RoutePolicies = map[string]config.SSRFRoutePolicyConfig{
		"corp": corpPolicy(
			[]string{"corp.example"},
			[]string{"10.0.0.0/8"},
			[]int{443}, // only 443 allowed, but request is http (port 80)
		),
	}
	c := httpclient.New(cfg, nil)
	c.SetResolver(resolver)

	// http:// derives effective port 80; policy only allows 443.
	_, err := c.Get(context.Background(), "http://internal.corp.example/api")
	if !httpclient.IsSSRFError(err) {
		t.Errorf("expected SSRF error when port rule fails, got: %v", err)
	}
}

// TestRoutePolicy_PrivateHostDeniedWhenAllowedPortsEmpty verifies that private
// route evaluation fails closed when a route policy omits AllowedPorts.
func TestRoutePolicy_PrivateHostDeniedWhenAllowedPortsEmpty(t *testing.T) {
	resolver := &fixedResolver{entries: map[string][]net.IPAddr{
		"internal.corp.example": {{IP: net.ParseIP("10.0.1.50")}},
	}}

	cfg := outboundtestutil.StrictShortTimeoutConfig()
	cfg.SSRF.RoutePolicy = "corp"
	cfg.SSRF.RoutePolicies = map[string]config.SSRFRoutePolicyConfig{
		"corp": corpPolicy(
			[]string{"corp.example"},
			[]string{"10.0.0.0/8"},
			nil,
		),
	}
	c := httpclient.New(cfg, nil)
	c.SetResolver(resolver)

	_, err := c.Get(context.Background(), "http://internal.corp.example/api")
	if !httpclient.IsSSRFError(err) {
		t.Errorf("expected SSRF error when allowed ports are omitted, got: %v", err)
	}
}

// TestRoutePolicy_MixedResolvedIPsFailClosed verifies all-records semantics:
// when a hostname resolves to both a public IP and a private IP that does not
// satisfy the CIDR rule, the whole request is blocked.
func TestRoutePolicy_MixedResolvedIPsFailClosed(t *testing.T) {
	resolver := &fixedResolver{entries: map[string][]net.IPAddr{
		"mixed.corp.example": {
			{IP: net.ParseIP("1.2.3.4")},     // public: would pass on its own
			{IP: net.ParseIP("192.168.1.1")}, // private: not in 10.0.0.0/8
		},
	}}

	cfg := outboundtestutil.StrictShortTimeoutConfig()
	cfg.SSRF.RoutePolicy = "corp"
	cfg.SSRF.RoutePolicies = map[string]config.SSRFRoutePolicyConfig{
		"corp": corpPolicy(
			[]string{"corp.example"},
			[]string{"10.0.0.0/8"}, // 192.168.1.1 not covered
			[]int{80, 443},
		),
	}
	c := httpclient.New(cfg, nil)
	c.SetResolver(resolver)

	_, err := c.Get(context.Background(), "http://mixed.corp.example/api")
	if !httpclient.IsSSRFError(err) {
		t.Errorf("expected SSRF error when any resolved IP fails policy (all-records), got: %v", err)
	}
}

// TestRoutePolicy_PrivateIPLiteralBlockedByDefault verifies that a private IP
// literal is blocked in strict mode when allow_ip_literals is false (default).
func TestRoutePolicy_PrivateIPLiteralBlockedByDefault(t *testing.T) {
	cfg := outboundtestutil.StrictShortTimeoutConfig()
	cfg.SSRF.RoutePolicy = "corp"
	cfg.SSRF.RoutePolicies = map[string]config.SSRFRoutePolicyConfig{
		"corp": {
			AllowPrivateCIDRs: []string{"10.0.0.0/8"},
			AllowedPorts:      []int{80, 443},
			AllowIPLiterals:   false, // default: IP literals not allowed
		},
	}
	c := httpclient.New(cfg, nil)

	_, err := c.Get(context.Background(), "http://10.0.0.1/api")
	if !httpclient.IsSSRFError(err) {
		t.Errorf("expected SSRF error for IP literal with allow_ip_literals=false, got: %v", err)
	}
}

// TestRoutePolicy_PrivateIPLiteralAllowedWithPolicy verifies that a private IP
// literal is allowed when allow_ip_literals=true, the IP is in the CIDR, and
// the port is permitted. The request fails with a connection error, not SSRF.
func TestRoutePolicy_PrivateIPLiteralAllowedWithPolicy(t *testing.T) {
	cfg := outboundtestutil.StrictShortTimeoutConfig()
	cfg.SSRF.RoutePolicy = "corp"
	cfg.SSRF.RoutePolicies = map[string]config.SSRFRoutePolicyConfig{
		"corp": {
			AllowPrivateCIDRs: []string{"10.0.0.0/8"},
			AllowedPorts:      []int{80},
			AllowIPLiterals:   true,
		},
	}
	c := httpclient.New(cfg, nil)

	_, err := c.Get(context.Background(), "http://10.0.0.1/api")
	if httpclient.IsSSRFError(err) {
		t.Errorf("route policy should allow this IP literal, got SSRF error: %v", err)
	}
}

// TestRoutePolicy_RedirectRevalidationWithAllowedPolicy verifies end-to-end
// that a redirect to the same host is followed when the route policy allows
// the (loopback) destination. Both the initial preflight and the redirect
// SSRF check must pass for the redirect to succeed.
func TestRoutePolicy_RedirectRevalidationWithAllowedPolicy(t *testing.T) {
	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/target", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Extract the actual port httptest chose so the route policy can allow it.
	u, _ := url.Parse(server.URL)
	port, _ := strconv.Atoi(u.Port())

	cfg := outboundtestutil.StrictNoneOutboundConfig()
	cfg.TimeoutMS = 5000
	cfg.ConnectTimeoutMS = 2000
	cfg.SSRF.RoutePolicy = "local"
	cfg.SSRF.RoutePolicies = map[string]config.SSRFRoutePolicyConfig{
		"local": {
			AllowPrivateCIDRs: []string{"127.0.0.0/8"},
			AllowedPorts:      []int{port},
			AllowIPLiterals:   true, // server is at 127.0.0.1 (IP literal)
		},
	}
	c := httpclient.New(cfg, nil)

	resp, err := c.Get(context.Background(), server.URL+"/start")
	if err != nil {
		t.Fatalf("expected redirect to be followed with matching route policy, got: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if atomic.LoadInt32(&requestCount) < 2 {
		t.Error("expected redirect to be followed (at least 2 requests)")
	}
}

// TestRoutePolicy_ProxyTrustedWhileDestinationPolicyEnforced verifies that
// configuring a proxy does not bypass destination SSRF route policy checks.
// The proxy hop is trusted (operator-controlled) but the private destination
// must still satisfy route policy or be blocked.
func TestRoutePolicy_ProxyTrustedWhileDestinationPolicyEnforced(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("proxy should not be reached for policy-blocked destination")
		w.WriteHeader(http.StatusOK)
	}))
	defer proxy.Close()

	resolver := &fixedResolver{entries: map[string][]net.IPAddr{
		"internal.nopolicy.example": {{IP: net.ParseIP("10.0.2.1")}},
	}}

	// Route policy does NOT include "nopolicy.example" in AllowPrivateHostSuffixes.
	cfg := outboundtestutil.StrictNoneOutboundConfig()
	cfg.SSRF.RoutePolicy = "corp"
	cfg.SSRF.RoutePolicies = map[string]config.SSRFRoutePolicyConfig{
		"corp": corpPolicy(
			[]string{"corp.example"}, // nopolicy.example not listed
			[]string{"10.0.0.0/8"},
			[]int{80, 443},
		),
	}
	cfg.ProxyURL = proxy.URL
	c := httpclient.New(cfg, nil)
	c.SetResolver(resolver)

	_, err := c.Get(context.Background(), "http://internal.nopolicy.example/api")
	if !httpclient.IsSSRFError(err) {
		t.Errorf("expected SSRF error: proxy trust must not bypass destination policy, got: %v", err)
	}
}

// TestClient_LegacySSRFModeCompatibility verifies that a caller that sets only
// the legacy SSRFMode shim (and leaves SSRF.Mode empty) still gets strict-mode
// enforcement. This covers programmatic callers that have not yet migrated to
// the nested SSRF.Mode field.
func TestClient_LegacySSRFModeCompatibility(t *testing.T) {
	cfg := &config.OutboundHTTPConfig{
		SSRFMode:         "strict", // legacy shim only; SSRF.Mode intentionally empty
		TimeoutMS:        500,
		ConnectTimeoutMS: 200,
		MaxRedirects:     1,
		MaxResponseBytes: 1048576,
	}
	c := httpclient.New(cfg, nil)

	_, err := c.Get(context.Background(), "http://127.0.0.1/test")
	if err == nil {
		t.Fatal("expected SSRF error when legacy SSRFMode=strict and SSRF.Mode is empty")
	}
	if !httpclient.IsSSRFError(err) {
		t.Errorf("expected SSRF-classified error, got: %v", err)
	}
}

// TestClient_NoPolicyErrorDistinct verifies that the error message when a
// private hostname resolves but no route policy is configured is distinct from
// the suffix-mismatch message. Both are SSRF errors, but the text must reflect
// which invariant failed so operators can diagnose configuration problems.
func TestClient_NoPolicyErrorDistinct(t *testing.T) {
	resolver := &fixedResolver{entries: map[string][]net.IPAddr{
		"internal.example.com": {{IP: net.ParseIP("10.0.1.50")}},
	}}

	// Strict mode with no RoutePolicy configured.
	cfg := outboundtestutil.StrictShortTimeoutConfig() // no RoutePolicy or RoutePolicies set
	c := httpclient.New(cfg, nil)
	c.SetResolver(resolver)

	_, err := c.Get(context.Background(), "http://internal.example.com/api")
	if !httpclient.IsSSRFError(err) {
		t.Fatalf("expected SSRF error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "no active route policy") {
		t.Errorf("expected 'no active route policy' in error when no policy is set, got: %v", err)
	}
	if strings.Contains(err.Error(), "host suffix") {
		t.Errorf("error must not mention host suffix when the problem is a missing policy, got: %v", err)
	}
}

// TestRoutePolicy_EnvProxyNOProxyCannotBypassDestinationChecks verifies that
// NO_PROXY routing a request direct does not bypass route-policy enforcement.
// The destination resolves to a private IP; the route policy does not allow it.
func TestRoutePolicy_EnvProxyNOProxyCannotBypassDestinationChecks(t *testing.T) {
	var proxyHit atomic.Bool
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyHit.Store(true)
		t.Error("proxy must not be reached: preflight SSRF check fires first")
		w.WriteHeader(http.StatusOK)
	}))
	defer proxy.Close()

	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("http_proxy", proxy.URL)
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("https_proxy", "")
	t.Setenv("ALL_PROXY", "")
	t.Setenv("all_proxy", "")
	t.Setenv("NO_PROXY", "10.0.2.1")
	t.Setenv("no_proxy", "10.0.2.1")

	resolver := &fixedResolver{entries: map[string][]net.IPAddr{
		"internal.nopolicy.example": {{IP: net.ParseIP("10.0.2.1")}},
	}}

	cfg := outboundtestutil.StrictNoneOutboundConfig()
	cfg.SSRF.RoutePolicy = "corp"
	cfg.SSRF.RoutePolicies = map[string]config.SSRFRoutePolicyConfig{
		"corp": corpPolicy(
			[]string{"corp.example"}, // nopolicy.example not listed
			[]string{"10.0.0.0/8"},
			[]int{80},
		),
	}
	cfg.ProxyEnvFallback = true
	c := httpclient.New(cfg, nil)
	c.SetResolver(resolver)

	_, err := c.Get(context.Background(), "http://internal.nopolicy.example/api")
	if !httpclient.IsSSRFError(err) {
		t.Errorf("expected SSRF error: NO_PROXY routing direct must not bypass destination policy, got: %v", err)
	}
	if proxyHit.Load() {
		t.Error("proxy must not be hit; preflight SSRF check must fire before proxy decision")
	}
}
