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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client/outboundtestutil"
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
