// Package client provides a safe outbound HTTP client with SSRF protections.
// See client.go for the concrete implementation.
//
// This file holds the SSRF and route-policy enforcement cluster. The Client
// methods here are invoked from the dial check, the DoWithOptions preflight,
// and the redirect revalidation in client.go. The pure helpers
// (hostMatchesSuffix, ipMatchesCIDRs, portAllowed) evaluate an active route
// policy and have no dependency on Client state.

package client

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

// activeRoutePolicy returns the named active route policy, or nil if none is
// configured. Returns nil when RoutePolicy is empty or the name is not found.
func (c *Client) activeRoutePolicy() *config.SSRFRoutePolicyConfig {
	name := c.cfg.SSRF.RoutePolicy
	if name == "" || c.cfg.SSRF.RoutePolicies == nil {
		return nil
	}
	p, ok := c.cfg.SSRF.RoutePolicies[name]
	if !ok {
		return nil
	}
	return &p
}

// checkSSRFURL runs a preflight SSRF check for a URL target.
// Derives the effective port from scheme defaults when the URL omits a port.
// Fails closed when the effective port cannot be derived (unknown scheme).
func (c *Client) checkSSRFURL(ctx context.Context, u *url.URL) error {
	port := effectivePort(u)
	if port == "" {
		return fmt.Errorf("%w: cannot derive effective port for scheme %q", ErrSSRFBlocked, u.Scheme)
	}
	return c.checkSSRFHostPort(ctx, u.Hostname(), port)
}

// checkSSRF validates that the address is not a blocked destination.
// The addr is in host:port format from the dialer.
func (c *Client) checkSSRF(ctx context.Context, addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
		port = ""
	}
	return c.checkSSRFHostPort(ctx, host, port)
}

// checkSSRFHostPort is the core SSRF enforcement function.
//
// Public destinations pass unconditionally. Private destinations require an
// active route policy where all three checks pass together: hostname suffix,
// resolved IP/CIDR, and destination port (all-records semantics: fail closed
// if any resolved address fails policy).
func (c *Client) checkSSRFHostPort(ctx context.Context, host, port string) error {
	// Strip IPv6 brackets if present.
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}

	lowerHost := strings.ToLower(host)
	if lowerHost == "localhost" || lowerHost == "localhost.localdomain" {
		return fmt.Errorf("%w: localhost is blocked", ErrSSRFBlocked)
	}

	policy := c.activeRoutePolicy()

	// IP literal: check allow_ip_literals then CIDR and port rules.
	if ip := net.ParseIP(host); ip != nil {
		return c.checkIPWithPolicy(ip, port, policy)
	}

	// Hostname: resolve all A and AAAA records (all-records semantics).
	// Fail closed if any private IP fails policy.
	ipAddrs, err := c.getResolver().LookupIPAddr(ctx, host)
	if err != nil {
		return fmt.Errorf("%w: %s: %v", ErrHostUnresolvable, host, err)
	}

	// Evaluate host suffix match once; it applies to every private IP result.
	hostAllowed := hostMatchesSuffix(lowerHost, policy)

	for _, ipAddr := range ipAddrs {
		ip := ipAddr.IP
		if c.isAllowedIP(ip) {
			continue // public IP: always allowed
		}
		// Private IP: all three checks must pass together.
		if policy == nil {
			return fmt.Errorf("%w: %s resolves to private IP %s and no active route policy is configured",
				ErrSSRFBlocked, host, ip)
		}
		if !hostAllowed {
			return fmt.Errorf("%w: %s resolves to private IP %s and host suffix is not in allowed list",
				ErrSSRFBlocked, host, ip)
		}
		if !ipMatchesCIDRs(ip, policy) {
			return fmt.Errorf("%w: %s resolves to IP %s not in allowed private CIDRs",
				ErrSSRFBlocked, host, ip)
		}
		if !portAllowed(port, policy) {
			return fmt.Errorf("%w: destination port %s is not in allowed ports",
				ErrSSRFBlocked, port)
		}
	}

	return nil
}

// checkIPWithPolicy validates a private IP literal against the active route policy.
// Public IPs are always allowed. Private IPs require allow_ip_literals=true
// plus matching CIDR and port rules.
func (c *Client) checkIPWithPolicy(ip net.IP, port string, policy *config.SSRFRoutePolicyConfig) error {
	if c.isAllowedIP(ip) {
		return nil
	}
	if policy == nil || !policy.AllowIPLiterals {
		return fmt.Errorf("%w: IP %s is blocked (allow_ip_literals=false)", ErrSSRFBlocked, ip)
	}
	if !ipMatchesCIDRs(ip, policy) {
		return fmt.Errorf("%w: IP %s not in allowed private CIDRs", ErrSSRFBlocked, ip)
	}
	if !portAllowed(port, policy) {
		return fmt.Errorf("%w: destination port %s is not in allowed ports", ErrSSRFBlocked, port)
	}
	return nil
}

// isAllowedIP reports whether the IP is a public address.
// Returns false for loopback, private, link-local, unspecified, and multicast.
func (c *Client) isAllowedIP(ip net.IP) bool {
	return !ip.IsLoopback() &&
		!ip.IsPrivate() &&
		!ip.IsLinkLocalUnicast() &&
		!ip.IsLinkLocalMulticast() &&
		!ip.IsUnspecified() &&
		!ip.IsMulticast()
}

// hostMatchesSuffix reports whether host matches any allowed private host suffix
// in the route policy. Empty entries are skipped. A single leading dot in a
// suffix entry (e.g. ".internal") is stripped before comparison so that
// operators using the common "dot-TLD" notation get the expected behavior.
func hostMatchesSuffix(host string, policy *config.SSRFRoutePolicyConfig) bool {
	if policy == nil {
		return false
	}
	for _, suffix := range policy.AllowPrivateHostSuffixes {
		sfx := strings.ToLower(strings.TrimSpace(suffix))
		sfx = strings.TrimPrefix(sfx, ".") // normalize exactly one leading dot
		if sfx == "" {
			continue
		}
		if host == sfx || strings.HasSuffix(host, "."+sfx) {
			return true
		}
	}
	return false
}

// ipMatchesCIDRs reports whether ip falls within any allowed private CIDR in
// the route policy. Malformed CIDR entries are silently skipped.
func ipMatchesCIDRs(ip net.IP, policy *config.SSRFRoutePolicyConfig) bool {
	if policy == nil {
		return false
	}
	for _, cidr := range policy.AllowPrivateCIDRs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// portAllowed reports whether the destination port is explicitly permitted by
// the route policy. Private-route evaluation fails closed when the policy is
// nil, the AllowedPorts list is empty, or the port string cannot be parsed.
func portAllowed(port string, policy *config.SSRFRoutePolicyConfig) bool {
	if policy == nil || len(policy.AllowedPorts) == 0 {
		return false
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		return false
	}
	for _, p := range policy.AllowedPorts {
		if p == n {
			return true
		}
	}
	return false
}
