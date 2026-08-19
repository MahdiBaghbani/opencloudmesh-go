// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// Package realip provides trusted proxy utilities for extracting real client IP.
// This is the single authoritative location for X-Forwarded-* and X-Real-IP parsing.
// No other code in the repository should parse these headers directly.
package realip

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

const (
	schemeHTTP  = "http"
	schemeHTTPS = "https"
)

var (
	// ErrMalformedForwardedHeader reports an invalid forwarded header value from a trusted proxy.
	ErrMalformedForwardedHeader = errors.New("malformed forwarded header")
	// ErrMissingForwardedHeader reports a required forwarded header absent from a trusted proxy.
	ErrMissingForwardedHeader = errors.New("missing forwarded header")
	// ErrConflictingForwardedHeader reports incompatible forwarded header values from a trusted proxy.
	ErrConflictingForwardedHeader = errors.New("conflicting forwarded header")
)

// TrustedProxies manages IP-based trusted proxy detection.
type TrustedProxies struct {
	networks        []*net.IPNet
	strictForwarded bool
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

// EnableStrictForwarded turns on fail-closed forwarded-header parsing for requests
// whose immediate peer is a configured trusted proxy.
func (tp *TrustedProxies) EnableStrictForwarded() *TrustedProxies {
	tp.strictForwarded = true

	return tp
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
	ip, err := tp.clientIPFromRequest(r)
	if err != nil {
		return nil
	}

	return ip
}

// ClientIPFromRequest extracts the client IP, honoring forwarded headers only when
// the immediate peer is trusted. Malformed forwarded headers from a trusted peer
// fail closed when strict forwarded parsing is enabled.
func (tp *TrustedProxies) ClientIPFromRequest(r *http.Request) (net.IP, error) {
	return tp.clientIPFromRequest(r)
}

// ForwardedProto returns the request scheme, honoring X-Forwarded-Proto only when
// the immediate peer is trusted.
func (tp *TrustedProxies) ForwardedProto(r *http.Request) (string, error) {
	if !tp.peerIsTrusted(r) {
		return directRequestScheme(r), nil
	}

	if tp.strictForwarded {
		raw, err := strictForwardedHeaderValue(r.Header, "X-Forwarded-Proto")
		if err != nil {
			return "", err
		}

		return parseStrictXForwardedProto(raw)
	}

	proto := strings.TrimSpace(strings.ToLower(r.Header.Get("X-Forwarded-Proto")))
	if proto == schemeHTTP || proto == schemeHTTPS {
		return proto, nil
	}

	return directRequestScheme(r), nil
}

// ForwardedHost returns the request host, honoring X-Forwarded-Host only when
// the immediate peer is trusted.
func (tp *TrustedProxies) ForwardedHost(r *http.Request) (string, error) {
	if !tp.peerIsTrusted(r) {
		return r.Host, nil
	}

	if tp.strictForwarded {
		raw, err := strictForwardedHeaderValue(r.Header, "X-Forwarded-Host")
		if err != nil {
			return "", err
		}

		return parseStrictXForwardedHost(raw)
	}

	host := strings.TrimSpace(r.Header.Get("X-Forwarded-Host"))
	if host == "" {
		return r.Host, nil
	}

	return host, nil
}

// ApplyTrustedForwardedHeaders validates required forwarded headers when strict
// parsing is enabled and the immediate peer is trusted, then applies the
// validated scheme and host to the request before downstream handlers run.
func (tp *TrustedProxies) ApplyTrustedForwardedHeaders(r *http.Request) error {
	if tp == nil || !tp.strictForwarded || !tp.peerIsTrusted(r) {
		return nil
	}

	if _, err := tp.clientIPFromRequest(r); err != nil {
		return err
	}

	proto, err := tp.ForwardedProto(r)
	if err != nil {
		return err
	}

	host, err := tp.ForwardedHost(r)
	if err != nil {
		return err
	}

	if r.URL == nil {
		r.URL = &url.URL{}
	}

	r.URL.Scheme = proto
	r.Host = host

	if proto == schemeHTTPS {
		*r = *r.WithContext(contextWithValidatedHTTPS(r.Context()))
	}

	return nil
}

// Middleware validates and applies trusted forwarded headers before downstream
// handlers run. Malformed, missing, or conflicting forwarded values from a
// trusted immediate peer are rejected with HTTP 400.
func (tp *TrustedProxies) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := tp.ApplyTrustedForwardedHeaders(r); err != nil {
			http.Error(w, "invalid forwarded headers", http.StatusBadRequest)

			return
		}

		next.ServeHTTP(w, r)
	})
}

// GetClientIPString returns the client IP as a string for logging/rate limiting.
func (tp *TrustedProxies) GetClientIPString(r *http.Request) string {
	ip := tp.GetClientIP(r)
	if ip == nil {
		return "unknown"
	}

	return ip.String()
}

func (tp *TrustedProxies) directPeerIP(r *http.Request) net.IP {
	return parseRemoteAddr(r.RemoteAddr)
}

func (tp *TrustedProxies) peerIsTrusted(r *http.Request) bool {
	directIP := tp.directPeerIP(r)

	return directIP != nil && tp.IsTrusted(directIP)
}

func (tp *TrustedProxies) clientIPFromRequest(r *http.Request) (net.IP, error) {
	directIP := tp.directPeerIP(r)
	if directIP == nil || !tp.IsTrusted(directIP) {
		return directIP, nil
	}

	if tp.strictForwarded {
		raw, err := strictForwardedHeaderValue(r.Header, "X-Forwarded-For")
		if err != nil {
			return nil, err
		}

		return tp.clientIPFromStrictXForwardedFor(raw)
	}

	return permissiveClientIP(r, directIP), nil
}

// RequestUsesHTTPS reports whether the request arrived over HTTPS transport.
// Secure cookies use this helper. Direct TLS (r.TLS != nil) counts as HTTPS.
// In terminated mode, TrustedProxies middleware sets a validated marker only
// after all required forwarded-header checks succeed for a trusted immediate
// peer with X-Forwarded-Proto=https. Raw URL scheme is not consulted.
func RequestUsesHTTPS(r *http.Request) bool {
	if r == nil {
		return false
	}

	if r.TLS != nil {
		return true
	}

	return validatedHTTPSFromContext(r.Context())
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

func permissiveClientIP(r *http.Request, directIP net.IP) net.IP {
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		xri := r.Header.Get("X-Real-IP")
		if xri != "" {
			if ip := net.ParseIP(strings.TrimSpace(xri)); ip != nil {
				return ip
			}
		}

		return directIP
	}

	parts := strings.Split(xff, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if ip := net.ParseIP(part); ip != nil {
			return ip
		}
	}

	return directIP
}

func directRequestScheme(r *http.Request) string {
	if r.TLS != nil {
		return schemeHTTPS
	}

	if r.URL != nil && r.URL.Scheme != "" {
		return strings.ToLower(r.URL.Scheme)
	}

	return schemeHTTP
}

// parseRemoteAddr extracts the IP from net/http RemoteAddr format.
func parseRemoteAddr(addr string) net.IP {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return net.ParseIP(addr)
	}

	return net.ParseIP(host)
}
