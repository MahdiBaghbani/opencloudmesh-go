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

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client/outboundtestutil"
)

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
