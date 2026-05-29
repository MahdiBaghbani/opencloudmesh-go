// Package client provides a safe outbound HTTP client with SSRF protections.
// See client.go for the concrete implementation.
//
// This file holds the pure redirect and URL helpers in client.go. Most are
// used by the manual redirect flow, but effectivePort is also used by the SSRF
// preflight in Client.checkSSRFURL. They have no dependency on Client state.

package client

import (
	"net/http"
	"net/url"
	"strings"
)

// isSameHost checks if two URLs have the same host (hostname + effective port).
// Uses url.URL.Hostname() and url.URL.Port() for IPv6-safe comparisons.
// Effective port: missing port = scheme default (http=80, https=443).
// Explicit default port is equivalent to missing (https://example.com:443 == https://example.com).
func isSameHost(a, b *url.URL) bool {
	if !strings.EqualFold(a.Hostname(), b.Hostname()) {
		return false
	}
	return effectivePort(a) == effectivePort(b)
}

// effectivePort returns the effective port for a URL.
// Missing port = scheme default. Explicit default port = same as missing.
// Returns "" for unknown schemes.
func effectivePort(u *url.URL) string {
	port := u.Port()
	if port == "" {
		return defaultPort(u.Scheme)
	}
	// Normalize explicit default port to the canonical form.
	if port == defaultPort(u.Scheme) {
		return defaultPort(u.Scheme)
	}
	return port
}

// defaultPort returns the well-known default port for a scheme.
func defaultPort(scheme string) string {
	switch strings.ToLower(scheme) {
	case "http":
		return "80"
	case "https":
		return "443"
	default:
		return ""
	}
}

// copyRedirectHeaders copies safe headers to the redirect request.
// Authorization and signature headers are intentionally omitted.
func copyRedirectHeaders(src, dst *http.Request) {
	if ua := src.Header.Get("User-Agent"); ua != "" {
		dst.Header.Set("User-Agent", ua)
	}
	if accept := src.Header.Get("Accept"); accept != "" {
		dst.Header.Set("Accept", accept)
	}
}

// isRedirect returns true if the status code is a redirect.
func isRedirect(code int) bool {
	return code == http.StatusMovedPermanently ||
		code == http.StatusFound ||
		code == http.StatusSeeOther ||
		code == http.StatusTemporaryRedirect ||
		code == http.StatusPermanentRedirect
}
