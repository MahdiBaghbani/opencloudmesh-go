package client_test

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	outboundtestutil "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
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
			resp, err := client.Get(ctx, tt.url)
			if resp != nil {
				defer resp.Body.Close() //nolint:errcheck // test response body close
			}

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
	resp, err := client.Get(ctx, "http://localhost:99999/test")
	if resp != nil {
		defer resp.Body.Close() //nolint:errcheck // test response body close
	}

	// Should not be an SSRF error
	if httpclient.IsSSRFError(err) {
		t.Errorf("unexpected SSRF error when mode is off: %v", err)
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
			resp, err := client.Get(context.Background(), tt.url)
			if resp != nil {
				defer resp.Body.Close() //nolint:errcheck // test response body close
			}

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
	resp, err := client.Get(context.Background(), "http://this-domain-does-not-exist-12345.invalid/test")
	if resp != nil {
		defer resp.Body.Close() //nolint:errcheck // test response body close
	}

	if err == nil {
		t.Fatal("expected error for unresolvable host")
	}
	// The .invalid TLD is guaranteed to fail resolution (RFC 6761); the client
	// must classify this as ErrHostUnresolvable, not let it pass silently as a
	// generic connection error.
	if !httpclient.IsHostUnresolvable(err) {
		t.Errorf("expected host-unresolvable error, got: %v", err)
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
			resp, err := c.Get(ctx, tt.url)
			if resp != nil {
				defer resp.Body.Close() //nolint:errcheck // test response body close
			}

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
			resp, err := client.Get(context.Background(), tt.url)
			if resp != nil {
				defer resp.Body.Close() //nolint:errcheck // test response body close
			}

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

// blockingResolver simulates a DNS resolver that blocks until context is canceled.
type blockingResolver struct {
	unblockCh chan struct{}
}

func (r *blockingResolver) LookupIPAddr(ctx context.Context, _ string) ([]net.IPAddr, error) {
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

	resp, err := client.Get(ctx, "http://example.com/test")
	if resp != nil {
		defer resp.Body.Close() //nolint:errcheck // test response body close
	}

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
