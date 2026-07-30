package keyid

import (
	"errors"
	"fmt"
	"strings"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/hostport"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/instanceid"
)

// DefaultFragment is the default JWKS / signature key fragment for this repo.
const DefaultFragment = "key1"

// Kid holds a host#fragment key identifier per the OCM IETF contract.
type Kid struct {
	Scheme    string // optional; set when parsed from absolute URI
	Authority string // host or host:port (lowercase, no scheme)
	Fragment  string
}

// BuildKid returns the canonical host#fragment kid string.
func BuildKid(authority, fragment string) string {
	if fragment == "" {
		fragment = DefaultFragment
	}

	return authority + "#" + fragment
}

// ParseKid parses a host#fragment kid. An absolute http(s) keyId URI is
// accepted and normalized to host#fragment by extracting authority and fragment.
func ParseKid(kid string) (Kid, error) {
	kid = strings.TrimSpace(kid)
	if kid == "" {
		return Kid{}, errors.New("keyid: empty kid")
	}

	if strings.Contains(kid, "://") {
		return parseKidFromURI(kid)
	}

	hash := strings.LastIndex(kid, "#")
	if hash <= 0 || hash == len(kid)-1 {
		return Kid{}, fmt.Errorf("keyid: malformed kid %q: expected host#fragment", kid)
	}

	authority := strings.ToLower(kid[:hash])

	fragment := kid[hash+1:]
	if authority == "" || fragment == "" {
		return Kid{}, fmt.Errorf("keyid: malformed kid %q: expected host#fragment", kid)
	}

	if strings.Contains(authority, "/") {
		return Kid{}, fmt.Errorf("keyid: host#fragment kid %q must not contain a path", kid)
	}

	return Kid{Authority: authority, Fragment: fragment}, nil
}

// CanonicalJWKSAuthority returns the scheme and hostport-normalized authority
// used to fetch JWKS for a parsed kid. Host#fragment and absolute-URI kids use
// the same authority rules. Empty scheme defaults to https. Paths in authority
// are rejected.
func CanonicalJWKSAuthority(k Kid) (scheme, authority string, err error) {
	scheme = strings.ToLower(strings.TrimSpace(k.Scheme))
	if scheme == "" {
		scheme = "https"
	}

	if scheme != "http" && scheme != "https" {
		return "", "", fmt.Errorf("keyid: unsupported scheme %q", k.Scheme)
	}

	authority = strings.TrimSpace(k.Authority)
	if authority == "" {
		return "", "", errors.New("keyid: empty authority")
	}

	if strings.Contains(authority, "/") {
		return "", "", fmt.Errorf("keyid: authority %q must not contain a path", authority)
	}

	normalized, err := hostport.Normalize(authority, scheme)
	if err != nil {
		return "", "", fmt.Errorf("keyid: normalize JWKS authority: %w", err)
	}

	return scheme, normalized, nil
}

func parseKidFromURI(keyID string) (Kid, error) {
	u, err := Parse(keyID)
	if err != nil {
		return Kid{}, err
	}

	fragment := ""
	if idx := strings.LastIndex(keyID, "#"); idx >= 0 && idx < len(keyID)-1 {
		fragment = keyID[idx+1:]
	}

	if fragment == "" {
		return Kid{}, fmt.Errorf("keyid: URI keyId %q has no fragment", keyID)
	}

	return Kid{
		Scheme:    u.Scheme,
		Authority: strings.ToLower(AuthorityForCompareFromKeyID(u)),
		Fragment:  fragment,
	}, nil
}

// String returns the host#fragment representation.
func (k Kid) String() string {
	return BuildKid(k.Authority, k.Fragment)
}

// KidFromPublicOrigin derives a stable host#fragment kid from public_origin.
func KidFromPublicOrigin(publicOrigin, fragment string) (string, error) {
	if fragment == "" {
		fragment = DefaultFragment
	}

	rawHost, err := instanceid.ProviderFQDN(publicOrigin)
	if err != nil {
		return "", err
	}

	scheme := "https"
	if u, parseErr := Parse(publicOrigin); parseErr == nil {
		scheme = u.Scheme
	} else if strings.HasPrefix(strings.ToLower(publicOrigin), "http://") {
		scheme = "http"
	}

	authority, err := hostport.Normalize(rawHost, scheme)
	if err != nil {
		return "", fmt.Errorf("keyid: normalize provider authority: %w", err)
	}

	return BuildKid(authority, fragment), nil
}

// KidEqualsExact reports whether a signature keyid parameter is byte-for-byte
// equal to a JWKS kid. The OCM IETF contract requires the keyid value to
// equal the kid of the corresponding key in the signer's JWK Set, and
// verifiers must reject when no set kid equals keyid, so the exact resolver
// applies string equality only: no authority normalization, case folding, or
// prefix/substring matching.
// See https://github.com/cs3org/OCM-API/blob/6a0586183cbef10ecae9dedc42561806447eb2f5/IETF-OCM.md#L846-L848
// See https://github.com/cs3org/OCM-API/blob/6a0586183cbef10ecae9dedc42561806447eb2f5/IETF-OCM.md#L928-L933
func KidEqualsExact(keyidParam, jwksKid string) bool {
	return keyidParam == jwksKid
}
