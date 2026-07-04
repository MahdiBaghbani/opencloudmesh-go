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

// ParseKid parses a host#fragment kid. A legacy absolute http(s) keyId URI is
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

	return Kid{Authority: authority, Fragment: fragment}, nil
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

// KidMatches reports whether a signature keyid parameter matches a JWKS kid.
func KidMatches(keyidParam, jwksKid string) bool {
	parsed, err := ParseKid(keyidParam)
	if err != nil {
		return false
	}
	jwks, err := ParseKid(jwksKid)
	if err != nil {
		return false
	}
	return parsed.Authority == jwks.Authority && parsed.Fragment == jwks.Fragment
}
