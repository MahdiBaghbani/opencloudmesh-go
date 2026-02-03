// Package address provides OCM address parsing and formatting helpers.
// OCM addresses use the format identifier@host[:port], where the identifier
// is separated from the host by the last '@' (the identifier may contain '@').
package address

import (
	"encoding/base64"
	"fmt"
	"regexp"
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
// Deprecated: uses StdEncoding (not Reva-compatible). Use FormatOutgoingOCMAddressFromUserID
// or EncodeFederatedOpaqueID instead. Will be removed in Phase 3.
func FormatOutgoing(userID string, providerFQDN string) string {
	return base64.StdEncoding.EncodeToString([]byte(userID)) + "@" + providerFQDN
}

// EncodeFederatedOpaqueID encodes a userID and idp into a Reva-style
// federated opaque ID: base64url_padded(userID + "@" + idp).
func EncodeFederatedOpaqueID(userID string, idp string) string {
	return base64.URLEncoding.EncodeToString([]byte(userID + "@" + idp))
}

// DecodeFederatedOpaqueID attempts to decode a Reva-style federated opaque ID.
// Tries (in order): padded base64url, raw base64url, standard base64.
// Returns ok=false if decode fails or decoded payload has no '@'.
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

// FormatOutgoingOCMAddressFromUserID builds an OCM address for outgoing
// protocol fields (owner, sender): identifier is a Reva-style federated
// opaque ID, provider is appended after '@'.
func FormatOutgoingOCMAddressFromUserID(userID, provider string) string {
	return EncodeFederatedOpaqueID(userID, provider) + "@" + provider
}

// base64LikeCharset matches strings composed entirely of base64/base64url characters.
var base64LikeCharset = regexp.MustCompile(`^[A-Za-z0-9+/=_-]+$`)

// LooksLikeBase64 returns true if s is non-empty and matches the base64/base64url charset.
func LooksLikeBase64(s string) bool {
	return base64LikeCharset.MatchString(s)
}
