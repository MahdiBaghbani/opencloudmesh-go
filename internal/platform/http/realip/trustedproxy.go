// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// Package realip provides trusted proxy utilities for extracting real client IP.
// This is the single authoritative location for X-Forwarded-For and X-Real-IP parsing.
// No other code in the repository should parse these headers directly.
package realip

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
)

// TrustedProxies manages IP-based trusted proxy detection.
type TrustedProxies struct {
	networks []*net.IPNet
}

// NewTrustedProxies creates a TrustedProxies from a list of CIDR strings.
// Invalid CIDRs are silently ignored.
func NewTrustedProxies(cidrs []string) *TrustedProxies {
	tp := &TrustedProxies{}

	for _, cidr := range cidrs {
		network, err := parseTrustedProxyCIDR(cidr)
		if err != nil || network == nil {
			continue
		}

		tp.networks = append(tp.networks, network)
	}

	return tp
}

// NewTrustedProxiesStrict creates a TrustedProxies and fails on the first
// invalid trusted proxy entry. Bare IPs are normalized to /32 or /128, matching
// NewTrustedProxies semantics.
func NewTrustedProxiesStrict(cidrs []string) (*TrustedProxies, error) {
	tp := &TrustedProxies{}

	for _, cidr := range cidrs {
		network, err := parseTrustedProxyCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("trusted proxy %q: %w", cidr, err)
		}

		if network == nil {
			return nil, fmt.Errorf("trusted proxy %q: invalid CIDR or IP", cidr)
		}

		tp.networks = append(tp.networks, network)
	}

	return tp, nil
}

func parseTrustedProxyCIDR(cidr string) (*net.IPNet, error) {
	cidr = strings.TrimSpace(cidr)
	if cidr == "" {
		return nil, errors.New("empty trusted proxy entry")
	}

	_, network, err := net.ParseCIDR(cidr)
	if err == nil {
		return network, nil
	}

	ip := net.ParseIP(cidr)
	if ip == nil {
		return nil, fmt.Errorf("invalid CIDR or IP: %w", err)
	}

	if ip.To4() != nil {
		_, v4Net, parseErr := net.ParseCIDR(ip.String() + "/32")
		if parseErr != nil {
			return nil, fmt.Errorf("parse IPv4 /32 for %q: %w", cidr, parseErr)
		}

		return v4Net, nil
	}

	_, v6Net, parseErr := net.ParseCIDR(ip.String() + "/128")
	if parseErr != nil {
		return nil, fmt.Errorf("parse IPv6 /128 for %q: %w", cidr, parseErr)
	}

	return v6Net, nil
}

// IsTrusted returns true if the IP is within any trusted proxy range.
func (tp *TrustedProxies) IsTrusted(ip net.IP) bool {
	for _, network := range tp.networks {
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

// GetClientIP extracts the real client IP from a request.
// If the request comes from a trusted proxy, uses X-Forwarded-For.
// Otherwise uses the direct connection address.
func (tp *TrustedProxies) GetClientIP(r *http.Request) net.IP {
	// Get direct connection IP
	directIP := parseRemoteAddr(r.RemoteAddr)

	// If no trusted proxies configured or direct IP not trusted, use direct IP
	if directIP == nil || !tp.IsTrusted(directIP) {
		return directIP
	}

	// Direct IP is trusted, check X-Forwarded-For
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		// Also check X-Real-IP
		xri := r.Header.Get("X-Real-IP")
		if xri != "" {
			if ip := net.ParseIP(strings.TrimSpace(xri)); ip != nil {
				return ip
			}
		}

		return directIP
	}

	// X-Forwarded-For can contain multiple IPs, take the first one
	// Format: "client, proxy1, proxy2"
	parts := strings.Split(xff, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if ip := net.ParseIP(part); ip != nil {
			return ip
		}
	}

	return directIP
}

// parseRemoteAddr extracts the IP from net/http RemoteAddr format.
func parseRemoteAddr(addr string) net.IP {
	// RemoteAddr is typically "ip:port" or "[ip]:port" for IPv6
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// Maybe it's just an IP
		return net.ParseIP(addr)
	}

	return net.ParseIP(host)
}

// GetClientIPString returns the client IP as a string for logging/rate limiting.
func (tp *TrustedProxies) GetClientIPString(r *http.Request) string {
	ip := tp.GetClientIP(r)
	if ip == nil {
		return "unknown"
	}

	return ip.String()
}
