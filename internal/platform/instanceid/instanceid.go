// Package instanceid derives instance public identity from config.PublicOrigin.
package instanceid

import (
	"fmt"
	"net/url"
	"strings"
)

// NormalizePublicOrigin applies cosmetic-only normalization to a public origin:
// trim a single trailing slash and lowercase scheme + hostname.
// It does NOT strip default ports.
func NormalizePublicOrigin(publicOrigin string) (string, error) {
	u, err := url.Parse(publicOrigin)
	if err != nil {
		return "", fmt.Errorf("instanceid: invalid public origin: %w", err)
	}

	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("instanceid: public origin must be an absolute URL with scheme and host: %q", publicOrigin)
	}

	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Host)

	normalized := scheme + "://" + host
	return normalized, nil
}

// ProviderFQDN returns host[:port] from a public origin URL,
// as used for instance identity.
func ProviderFQDN(publicOrigin string) (string, error) {
	u, err := url.Parse(publicOrigin)
	if err != nil {
		return "", fmt.Errorf("instanceid: invalid public origin: %w", err)
	}

	if u.Host == "" {
		return "", fmt.Errorf("instanceid: public origin has no host: %q", publicOrigin)
	}

	return strings.ToLower(u.Host), nil
}

// Hostname returns the hostname only (no port) from a public origin URL.
// Used for TLS certificate generation.
func Hostname(publicOrigin string) (string, error) {
	u, err := url.Parse(publicOrigin)
	if err != nil {
		return "", fmt.Errorf("instanceid: invalid public origin: %w", err)
	}

	if u.Host == "" {
		return "", fmt.Errorf("instanceid: public origin has no host: %q", publicOrigin)
	}

	hostname := u.Hostname() // strips port and brackets from IPv6
	return strings.ToLower(hostname), nil
}
