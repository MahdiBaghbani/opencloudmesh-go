// Package address provides OCM address parsing and formatting helpers.
// OCM addresses use the format identifier@host[:port], where the identifier
// is separated from the host by the last '@' (the identifier may contain '@').
package address

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// Parse splits an OCM address on the last '@' into identifier and provider.
// The identifier may contain '@' (e.g. email addresses).
// The provider must not contain scheme ("://") or path ("/").
// Both parts must be non-empty.
func Parse(addr string) (identifier, provider string, err error) {
	if addr == "" {
		return "", "", fmt.Errorf("empty OCM address")
	}

	idx := strings.LastIndex(addr, "@")
	if idx < 0 {
		return "", "", fmt.Errorf("invalid OCM address: missing '@' separator in %q", addr)
	}

	identifier = addr[:idx]
	provider = addr[idx+1:]

	if identifier == "" {
		return "", "", fmt.Errorf("invalid OCM address: empty identifier in %q", addr)
	}
	if provider == "" {
		return "", "", fmt.Errorf("invalid OCM address: empty provider in %q", addr)
	}

	if strings.Contains(provider, "://") {
		return "", "", fmt.Errorf("invalid OCM address: provider contains scheme in %q", addr)
	}
	if strings.Contains(provider, "/") {
		return "", "", fmt.Errorf("invalid OCM address: provider contains path in %q", addr)
	}

	return identifier, provider, nil
}

// FormatOutgoing builds a Reva-compatible OCM address for outgoing protocol fields.
// Returns base64(userID) + "@" + providerFQDN.
func FormatOutgoing(userID string, providerFQDN string) string {
	return base64.StdEncoding.EncodeToString([]byte(userID)) + "@" + providerFQDN
}
