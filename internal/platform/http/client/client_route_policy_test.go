// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package client_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	outboundtestutil "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
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
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}

	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatalf("parse server port: %v", err)
	}

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

	resp, err := c.Get(context.Background(), server.URL+"/api") //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	if httpclient.IsSSRFError(err) {
		t.Errorf("route policy should allow this private host, got SSRF error: %v", err)
	}

	if err != nil {
		t.Fatalf("expected successful request, got: %v", err)
	}

	defer outboundtestutil.MustClose(t, resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

// TestRoutePolicy_LeadingDotSuffixNormalized verifies that suffix entries
// written with a leading dot (e.g. ".internal") are normalized before matching
// so that "service.internal" is correctly allowed.
func TestRoutePolicy_LeadingDotSuffixNormalized(t *testing.T) {
	t.Parallel()

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

	resp, err := c.Get(context.Background(), "http://service.internal/api") //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	if resp != nil {
		defer outboundtestutil.MustClose(t, resp.Body)
	}

	if httpclient.IsSSRFError(err) {
		t.Errorf(".internal suffix should match service.internal after normalization, got SSRF error: %v", err)
	}
}

// TestRoutePolicy_PrivateHostDeniedWhenSuffixFails verifies that a private IP
// is blocked when the hostname does not match any allowed suffix.
func TestRoutePolicy_PrivateHostDeniedWhenSuffixFails(t *testing.T) {
	t.Parallel()

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

	resp, err := c.Get(context.Background(), "http://other.noncorp.example/api") //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	if resp != nil {
		defer outboundtestutil.MustClose(t, resp.Body)
	}

	if !httpclient.IsSSRFError(err) {
		t.Errorf("expected SSRF error when host suffix does not match policy, got: %v", err)
	}
}

// TestRoutePolicy_PrivateHostDeniedWhenCIDRFails verifies that a private IP is
// blocked when the resolved address is not in any allowed CIDR.
func TestRoutePolicy_PrivateHostDeniedWhenCIDRFails(t *testing.T) {
	t.Parallel()

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

	resp, err := c.Get(context.Background(), "http://internal.corp.example/api") //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	if resp != nil {
		defer outboundtestutil.MustClose(t, resp.Body)
	}

	if !httpclient.IsSSRFError(err) {
		t.Errorf("expected SSRF error when resolved IP is not in allowed CIDR, got: %v", err)
	}
}

// TestRoutePolicy_PrivateHostDeniedWhenPortFails verifies that the same
// hostname is denied when the destination port is not in the allowed ports list.
func TestRoutePolicy_PrivateHostDeniedWhenPortFails(t *testing.T) {
	t.Parallel()

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
	resp, err := c.Get(context.Background(), "http://internal.corp.example/api") //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	if resp != nil {
		defer outboundtestutil.MustClose(t, resp.Body)
	}

	if !httpclient.IsSSRFError(err) {
		t.Errorf("expected SSRF error when port rule fails, got: %v", err)
	}
}

// TestRoutePolicy_PrivateHostDeniedWhenAllowedPortsEmpty verifies that private
// route evaluation fails closed when a route policy omits AllowedPorts.
func TestRoutePolicy_PrivateHostDeniedWhenAllowedPortsEmpty(t *testing.T) {
	t.Parallel()

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

	resp, err := c.Get(context.Background(), "http://internal.corp.example/api") //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	if resp != nil {
		defer outboundtestutil.MustClose(t, resp.Body)
	}

	if !httpclient.IsSSRFError(err) {
		t.Errorf("expected SSRF error when allowed ports are omitted, got: %v", err)
	}
}

// TestRoutePolicy_MixedResolvedIPsFailClosed verifies all-records semantics:
// when a hostname resolves to both a public IP and a private IP that does not
// satisfy the CIDR rule, the whole request is blocked.
func TestRoutePolicy_MixedResolvedIPsFailClosed(t *testing.T) {
	t.Parallel()

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

	resp, err := c.Get(context.Background(), "http://mixed.corp.example/api") //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	if resp != nil {
		defer outboundtestutil.MustClose(t, resp.Body)
	}

	if !httpclient.IsSSRFError(err) {
		t.Errorf("expected SSRF error when any resolved IP fails policy (all-records), got: %v", err)
	}
}

// TestRoutePolicy_PrivateIPLiteralBlockedByDefault verifies that a private IP
// literal is blocked in strict mode when allow_ip_literals is false (default).
func TestRoutePolicy_PrivateIPLiteralBlockedByDefault(t *testing.T) {
	t.Parallel()

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

	resp, err := c.Get(context.Background(), "http://10.0.0.1/api") //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	if resp != nil {
		defer outboundtestutil.MustClose(t, resp.Body)
	}

	if !httpclient.IsSSRFError(err) {
		t.Errorf("expected SSRF error for IP literal with allow_ip_literals=false, got: %v", err)
	}
}

// TestRoutePolicy_PrivateIPLiteralAllowedWithPolicy verifies that a private IP
// literal is allowed when allow_ip_literals=true, the IP is in the CIDR, and
// the port is permitted. The request fails with a connection error, not SSRF.
func TestRoutePolicy_PrivateIPLiteralAllowedWithPolicy(t *testing.T) {
	t.Parallel()

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

	resp, err := c.Get(context.Background(), "http://10.0.0.1/api") //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	if resp != nil {
		defer outboundtestutil.MustClose(t, resp.Body)
	}

	if httpclient.IsSSRFError(err) {
		t.Errorf("route policy should allow this IP literal, got SSRF error: %v", err)
	}
}
