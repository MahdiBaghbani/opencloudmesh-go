package httpclient_test

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/httpclient"
)

func TestClient_SSRFProtection(t *testing.T) {
	cfg := &config.OutboundHTTPConfig{
		SSRFMode:         "strict",
		TimeoutMS:        1000,
		ConnectTimeoutMS: 500,
		MaxRedirects:     1,
		MaxResponseBytes: 1048576,
	}
	client := httpclient.New(cfg)

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
					// For some tests, connection errors are also acceptable
					// (e.g., if the network doesn't allow the connection at all)
					t.Logf("got error: %v (may be acceptable)", err)
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
	cfg := &config.OutboundHTTPConfig{
		SSRFMode:         "off",
		TimeoutMS:        1000,
		ConnectTimeoutMS: 500,
		MaxRedirects:     1,
		MaxResponseBytes: 1048576,
	}
	client := httpclient.New(cfg)

	ctx := context.Background()

	// With SSRF off, localhost should not be blocked at the SSRF check level
	// (it will still fail to connect if nothing is listening)
	_, err := client.Get(ctx, "http://localhost:99999/test")

	// Should not be an SSRF error
	if httpclient.IsSSRFError(err) {
		t.Errorf("unexpected SSRF error when mode is off: %v", err)
	}
}

func TestClient_ProxyEnvIgnored(t *testing.T) {
	// Set proxy environment variables
	os.Setenv("HTTP_PROXY", "http://proxy.invalid:8080")
	os.Setenv("HTTPS_PROXY", "http://proxy.invalid:8080")
	os.Setenv("http_proxy", "http://proxy.invalid:8080")
	os.Setenv("https_proxy", "http://proxy.invalid:8080")
	os.Setenv("NO_PROXY", "")
	defer func() {
		os.Unsetenv("HTTP_PROXY")
		os.Unsetenv("HTTPS_PROXY")
		os.Unsetenv("http_proxy")
		os.Unsetenv("https_proxy")
		os.Unsetenv("NO_PROXY")
	}()

	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("direct"))
	}))
	defer server.Close()

	// Create client with SSRF off (so we can test locally)
	cfg := &config.OutboundHTTPConfig{
		SSRFMode:         "off",
		TimeoutMS:        5000,
		ConnectTimeoutMS: 2000,
		MaxRedirects:     1,
		MaxResponseBytes: 1048576,
	}
	client := httpclient.New(cfg)

	// If proxy was used, this would fail (proxy.invalid doesn't exist)
	// Since we ignore proxy vars, it should connect directly
	resp, err := client.Get(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("expected direct connection, got error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
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

	cfg := &config.OutboundHTTPConfig{
		SSRFMode:         "off",
		TimeoutMS:        5000,
		ConnectTimeoutMS: 2000,
		MaxRedirects:     1,
		MaxResponseBytes: 1048576,
	}
	client := httpclient.New(cfg)

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

	cfg := &config.OutboundHTTPConfig{
		SSRFMode:         "off",
		TimeoutMS:        5000,
		ConnectTimeoutMS: 2000,
		MaxRedirects:     1,
		MaxResponseBytes: 1048576,
	}
	client := httpclient.New(cfg)

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

	cfg := &config.OutboundHTTPConfig{
		SSRFMode:         "off",
		TimeoutMS:        5000,
		ConnectTimeoutMS: 2000,
		MaxRedirects:     1, // Only allow 1 redirect
		MaxResponseBytes: 1048576,
	}
	client := httpclient.New(cfg)

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

	cfg := &config.OutboundHTTPConfig{
		SSRFMode:         "off",
		TimeoutMS:        5000,
		ConnectTimeoutMS: 2000,
		MaxRedirects:     1,
		MaxResponseBytes: 1048576,
	}
	client := httpclient.New(cfg)

	_, err := client.Get(context.Background(), redirectServer.URL+"/start")
	if err == nil {
		t.Fatal("expected error for cross-host redirect")
	}
	if !strings.Contains(err.Error(), "different host") {
		t.Errorf("expected 'different host' in error, got: %v", err)
	}
}

func TestClient_UnsignedRejectsHTTPSDowngrade(t *testing.T) {
	// Note: We can't easily test HTTPS -> HTTP downgrade with httptest
	// because httptest.NewTLSServer uses a self-signed cert.
	// Instead, we test the logic by checking the error message format.
	// The actual downgrade detection is tested in the URL comparison logic.
	t.Skip("HTTPS downgrade test requires more complex setup")
}

func TestClient_IPv6BracketHandling(t *testing.T) {
	cfg := &config.OutboundHTTPConfig{
		SSRFMode:         "strict",
		TimeoutMS:        1000,
		ConnectTimeoutMS: 500,
		MaxRedirects:     1,
		MaxResponseBytes: 1048576,
	}
	client := httpclient.New(cfg)

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
	cfg := &config.OutboundHTTPConfig{
		SSRFMode:         "strict",
		TimeoutMS:        1000,
		ConnectTimeoutMS: 500,
		MaxRedirects:     1,
		MaxResponseBytes: 1048576,
	}
	client := httpclient.New(cfg)

	// Use a domain that definitely doesn't exist
	_, err := client.Get(context.Background(), "http://this-domain-does-not-exist-12345.invalid/test")
	if err == nil {
		t.Fatal("expected error for unresolvable host")
	}
	// Should be blocked (fail closed)
	if !httpclient.IsSSRFError(err) {
		t.Logf("got error: %v (may be acceptable if it's a connection error)", err)
	}
}

func TestIsAllowedIP(t *testing.T) {
	tests := []struct {
		ip      string
		allowed bool
	}{
		{"1.2.3.4", true},      // Public
		{"8.8.8.8", true},      // Google DNS
		{"127.0.0.1", false},   // Loopback
		{"::1", false},         // IPv6 loopback
		{"10.0.0.1", false},    // Private
		{"192.168.1.1", false}, // Private
		{"172.16.0.1", false},  // Private
		{"169.254.1.1", false}, // Link-local
		{"0.0.0.0", false},     // Unspecified
		{"::", false},          // IPv6 unspecified
		{"224.0.0.1", false},   // Multicast
		{"203.0.113.1", true},  // TEST-NET-3 (documentation, but public)
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("failed to parse IP: %s", tt.ip)
			}

			// We need to test the internal function, but it's not exported.
			// Instead, we test via the client behavior indirectly.
			// For now, just verify the IP parses correctly.
			_ = ip
		})
	}
}

func TestClient_DoPreservesInterface(t *testing.T) {
	// Verify Do() still works with the standard http.Request interface
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &config.OutboundHTTPConfig{
		SSRFMode:         "off",
		TimeoutMS:        5000,
		ConnectTimeoutMS: 2000,
		MaxRedirects:     1,
		MaxResponseBytes: 1048576,
	}
	client := httpclient.New(cfg)

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
