// Package address provides OCM address parsing and formatting.
// Format: identifier@host[:port]. Split on last '@'; identifier may contain '@'.
package address

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
)

// Parse splits an OCM address on the last '@' into identifier and provider.
// Identifier may contain '@' (e.g. email). Provider must not contain scheme or path.
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

// EncodeFederatedOpaqueID produces base64url(userID + "@" + idp) for protocol use.
func EncodeFederatedOpaqueID(userID string, idp string) string {
	return base64.URLEncoding.EncodeToString([]byte(userID + "@" + idp))
}

// DecodeFederatedOpaqueID decodes base64url; tries padded, raw, then std base64.
// Splits on last '@'. Returns ok=false if decode fails or payload invalid.
func DecodeFederatedOpaqueID(encoded string) (userID string, idp string, ok bool) {
	decodings := []*base64.Encoding{
		base64.URLEncoding,
		base64.RawURLEncoding,
		base64.StdEncoding,
	}

	for _, enc := range decodings {
		decoded, err := enc.DecodeString(encoded)
		if err != nil {
			continue
		}

		payload := string(decoded)
		idx := strings.LastIndex(payload, "@")
		if idx < 0 || idx == 0 || idx == len(payload)-1 {
			continue
		}

		return payload[:idx], payload[idx+1:], true
	}

	return "", "", false
}

// FormatOutgoingOCMAddressFromUserID builds identifier@provider for owner/sender; identifier = EncodeFederatedOpaqueID(userID, provider).
func FormatOutgoingOCMAddressFromUserID(userID, provider string) string {
	return EncodeFederatedOpaqueID(userID, provider) + "@" + provider
}

var base64LikeCharset = regexp.MustCompile(`^[A-Za-z0-9+/=_-]+$`)

// LooksLikeBase64 returns true if s is non-empty and matches base64-like charset.
func LooksLikeBase64(s string) bool {
	return base64LikeCharset.MatchString(s)
}
