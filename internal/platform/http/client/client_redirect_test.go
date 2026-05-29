package client_test

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client/outboundtestutil"
)

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
