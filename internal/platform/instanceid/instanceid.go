// Package instanceid is the single source of truth for deriving instance
// public identity from config.ExternalOrigin.
package instanceid

import (
	"fmt"
	"net/url"
	"strings"
)

// NormalizeExternalOrigin applies cosmetic-only normalization to an external origin:
// trim a single trailing slash and lowercase scheme + hostname.
// It does NOT strip default ports.
func NormalizeExternalOrigin(externalOrigin string) (string, error) {
	u, err := url.Parse(externalOrigin)
	if err != nil {
		return "", fmt.Errorf("instanceid: invalid external origin: %w", err)
	}

	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("instanceid: external origin must be an absolute URL with scheme and host: %q", externalOrigin)
	}

	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Host)

	normalized := scheme + "://" + host
	return normalized, nil
}

// ProviderFQDN returns host[:port] from an external origin URL,
// as used for provider_fqdn and instance identity.
func ProviderFQDN(externalOrigin string) (string, error) {
	u, err := url.Parse(externalOrigin)
	if err != nil {
		return "", fmt.Errorf("instanceid: invalid external origin: %w", err)
	}

	if u.Host == "" {
		return "", fmt.Errorf("instanceid: external origin has no host: %q", externalOrigin)
	}

	return strings.ToLower(u.Host), nil
}

// Hostname returns the hostname only (no port) from an external origin URL.
// Used for TLS certificate generation.
func Hostname(externalOrigin string) (string, error) {
	u, err := url.Parse(externalOrigin)
	if err != nil {
		return "", fmt.Errorf("instanceid: invalid external origin: %w", err)
	}

	if u.Host == "" {
		return "", fmt.Errorf("instanceid: external origin has no host: %q", externalOrigin)
	}

	hostname := u.Hostname() // strips port and brackets from IPv6
	return strings.ToLower(hostname), nil
}
