// Package hostport provides scheme-aware authority normalization for host[:port]
// comparison. It is the single source of truth for default-port equivalence in
// ocmgo. This normalizer is used for trust-group membership matching;
// denylist/allowlist use case-insensitive comparison only, not this normalizer.
// Both are ocmgo implementation choices. The OCM spec defines denylist/allowlist
// as IP-address based
// (https://github.com/cs3org/OCM-API/blob/6a0586183cbef10ecae9dedc42561806447eb2f5/IETF-OCM.md#L759-L762)
// and does not define FQDN matching.
package hostport

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// Normalize returns a lowercase, scheme-aware host[:port] with default ports
// stripped. Default ports: :443 for https, :80 for http.
//
// Rejects values containing "://" or "/" since all inputs are schemeless
// authorities. Preserves IPv6 bracket form (e.g. [::1], [::1]:9200).
func Normalize(authority string, scheme string) (string, error) {
	authority = strings.TrimSpace(authority)
	if authority == "" {
		return "", errors.New("hostport: empty authority")
	}

	if strings.Contains(authority, "://") {
		return "", fmt.Errorf("hostport: authority %q must not contain a scheme", authority)
	}

	if strings.Contains(authority, "/") {
		return "", fmt.Errorf("hostport: authority %q must not contain a path", authority)
	}

	// Use a dummy scheme so url.Parse handles IPv6 brackets and port splitting.
	dummy := "dummy://" + authority

	u, err := url.Parse(dummy)
	if err != nil {
		return "", fmt.Errorf("hostport: invalid authority %q: %w", authority, err)
	}

	hostname := strings.ToLower(u.Hostname())
	if hostname == "" {
		return "", fmt.Errorf("hostport: authority %q has no host", authority)
	}

	port := u.Port()
	scheme = strings.ToLower(scheme)

	if isDefaultPort(port, scheme) {
		port = ""
	}

	if port == "" {
		// IPv6 addresses need brackets when output as standalone authorities.
		if strings.Contains(hostname, ":") {
			return "[" + hostname + "]", nil
		}

		return hostname, nil
	}

	return net.JoinHostPort(hostname, port), nil
}

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
