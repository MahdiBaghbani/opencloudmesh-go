// Package keyid provides canonical parsing and comparison normalization for
// OCM keyId URIs. It is the single source of truth for remote peer keyId
// handling, unifying the previously duplicated implementations.
package keyid

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/hostport"
)

// Parsed holds the decomposed components of a keyId URI.
type Parsed struct {
	Scheme   string // "http" or "https"
	Hostname string // lowercased hostname (no brackets for IPv6)
	Port     string // explicit port if present, empty otherwise
}

// Parse parses a keyId URI and extracts its authority components.
// The parser is path-agnostic and fragment-agnostic: it accepts any path
// and fragment (including none). It uses url.Parse and lowercases the host.
//
// Strictness rules:
//   - Must be an absolute URI with scheme http or https.
//   - Must have a host.
//   - Userinfo is rejected.
//   - Query is allowed but ignored for authority extraction.
//   - Explicit ports (including :443 and :80) are preserved in the Parsed result.
func Parse(keyID string) (Parsed, error) {
	u, err := url.Parse(keyID)
	if err != nil {
		return Parsed{}, fmt.Errorf("keyid: invalid URI: %w", err)
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return Parsed{}, fmt.Errorf("keyid: scheme must be http or https, got %q", u.Scheme)
	}

	if u.Host == "" {
		return Parsed{}, errors.New("keyid: URI has no host")
	}

	if u.User != nil {
		return Parsed{}, errors.New("keyid: userinfo is not allowed in keyId URIs")
	}

	hostname := strings.ToLower(u.Hostname())
	port := u.Port()

	return Parsed{
		Scheme:   scheme,
		Hostname: hostname,
		Port:     port,
	}, nil
}

// Authority returns the authority string from a parsed keyId.
// IPv6 hostnames are always bracketed (e.g. [::1] or [::1]:9200) since
// authority strings require brackets per RFC 3986.
func Authority(p Parsed) string {
	if p.Port == "" {
		// IPv6 addresses must be bracketed in authority form.
		if strings.Contains(p.Hostname, ":") {
			return "[" + p.Hostname + "]"
		}
		return p.Hostname
	}

	return net.JoinHostPort(p.Hostname, p.Port)
}

// AuthorityForCompareFromKeyID returns a scheme-aware normalized authority
// for identity comparison. Default ports are stripped based on the keyId's
// own scheme: :443 for https, :80 for http.
//
// Uses hostport.Normalize internally to ensure a single normalization
// implementation across the codebase.
func AuthorityForCompareFromKeyID(p Parsed) string {
	authority := Authority(p)
	normalized, err := hostport.Normalize(authority, p.Scheme)
	if err != nil {
		// Authority was already parsed from a valid keyId URI, so this
		// should not fail. Fall back to the raw authority on error.
		return authority
	}
	return normalized
}

// AuthorityForCompareFromDeclaredPeer normalizes a schemeless declared peer
// authority (host or host:port) for identity comparison. The scheme parameter
// determines which default port is stripped (:443 for https, :80 for http).
//
// This is a convenience wrapper around hostport.Normalize. Non-keyId call
// sites (token handler, notifications, invites, shareWith provider match)
// should use hostport.Normalize directly instead of importing this package.
//
// On parse failure, an error is returned. Call sites that enforce mismatch
// must log and skip mismatch enforcement on error (do not introduce a new
// rejection path).
func AuthorityForCompareFromDeclaredPeer(peer string, scheme string) (string, error) {
	return hostport.Normalize(peer, scheme)
}
