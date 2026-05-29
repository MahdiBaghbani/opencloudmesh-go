package client_test

import (
	"context"
	"fmt"
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
