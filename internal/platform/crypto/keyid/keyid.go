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

// Authority returns the raw authority string from a parsed keyId.
// Returns "hostname" when no port is present, or "hostname:port" when a port
// is explicitly specified. IPv6 hostnames are not bracketed in the output
// (consistent with url.Hostname() behavior).
func Authority(p Parsed) string {
	if p.Port == "" {
		return p.Hostname
	}

	return net.JoinHostPort(p.Hostname, p.Port)
}

// AuthorityForCompareFromKeyID returns a scheme-aware normalized authority
// for identity comparison. Default ports are stripped based on the keyId's
// own scheme: :443 for https, :80 for http.
func AuthorityForCompareFromKeyID(p Parsed) string {
	return authorityForCompare(p.Hostname, p.Port, p.Scheme)
}

// AuthorityForCompareFromDeclaredPeer normalizes a schemeless declared peer
// authority (host or host:port) for identity comparison. The scheme parameter
// determines which default port is stripped (:443 for https, :80 for http).
//
// Leading and trailing whitespace is trimmed before parsing. The hostname is
// lowercased. Bracketed IPv6 addresses are supported.
//
// On parse failure, an error is returned. Call sites that enforce mismatch
// must log and skip mismatch enforcement on error (do not introduce a new
// rejection path).
func AuthorityForCompareFromDeclaredPeer(peer string, scheme string) (string, error) {
	peer = strings.TrimSpace(peer)
	if peer == "" {
		return "", errors.New("keyid: empty peer authority")
	}

	// Parse the peer as a host or host:port. We prepend a dummy scheme so
	// url.Parse can handle IPv6 brackets and port splitting correctly.
	dummy := "dummy://" + peer
	u, err := url.Parse(dummy)
	if err != nil {
		return "", fmt.Errorf("keyid: invalid peer authority %q: %w", peer, err)
	}

	hostname := strings.ToLower(u.Hostname())
	if hostname == "" {
		return "", fmt.Errorf("keyid: peer authority %q has no host", peer)
	}

	port := u.Port()
	scheme = strings.ToLower(scheme)

	return authorityForCompare(hostname, port, scheme), nil
}

// authorityForCompare strips the default port for the given scheme and
// returns the normalized authority for comparison.
func authorityForCompare(hostname, port, scheme string) string {
	if isDefaultPort(port, scheme) {
		return hostname
	}

	if port == "" {
		return hostname
	}

	return net.JoinHostPort(hostname, port)
}

// isDefaultPort returns true if the port is the default for the scheme.
func isDefaultPort(port, scheme string) bool {
	switch scheme {
	case "https":
		return port == "443"
	case "http":
		return port == "80"
	default:
		return false
	}
}
