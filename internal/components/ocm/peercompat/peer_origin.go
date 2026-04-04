// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package peercompat

import (
	"net/url"
	"strings"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/hostport"
)

// PeerOriginDecision is the typed peer-origin and host-validation decision.
type PeerOriginDecision struct {
	PeerDomain string
	Profile    string
	Scheme     string
	BaseURL    string
	AllowHTTP  bool
}

// ResolvePeerOrigin resolves peer origin and scheme for peer-boundary callers.
func (c *CompiledContract) ResolvePeerOrigin(peerInput string) PeerOriginDecision {
	peerDomain, inputScheme := peerDomainFromInput(peerInput)
	if peerDomain == "" {
		return PeerOriginDecision{}
	}

	profileName := "strict"
	allowHTTP := false
	scheme := "https"

	// Transitional behavior: preserve explicit scheme when no compiled contract
	// is available in the caller, so existing tests and nil-dependency paths keep
	// their current transport behavior.
	if c == nil {
		if inputScheme == "http" || inputScheme == "https" {
			scheme = inputScheme
		}
	} else if profile, ok := c.ProfileForPeer(peerDomain); ok {
		profileName = profile.Name
		allowHTTP = profile.Transport.AllowHTTP
		if allowHTTP {
			scheme = "http"
		}
	}

	return PeerOriginDecision{
		PeerDomain: peerDomain,
		Profile:    profileName,
		Scheme:     scheme,
		BaseURL:    scheme + "://" + peerDomain,
		AllowHTTP:  allowHTTP,
	}
}

// IsPeerAbsoluteURIAllowed validates an absolute URI against the resolved peer
// authority and transport policy.
func (c *CompiledContract) IsPeerAbsoluteURIAllowed(absoluteURI, peerInput string) bool {
	parsed, err := url.Parse(absoluteURI)
	if err != nil || parsed.Host == "" {
		return false
	}

	uriScheme := strings.ToLower(parsed.Scheme)
	if uriScheme != "http" && uriScheme != "https" {
		return false
	}

	// Keep legacy behavior for nil-contract call sites.
	if c == nil {
		return legacyAuthorityMatch(parsed.Host, peerInput, "https")
	}

	origin := c.ResolvePeerOrigin(peerInput)
	if origin.PeerDomain == "" {
		return false
	}
	if uriScheme == "http" && !origin.AllowHTTP {
		return false
	}

	return legacyAuthorityMatch(parsed.Host, origin.PeerDomain, uriScheme)
}

func peerDomainFromInput(peerInput string) (string, string) {
	input := strings.TrimSpace(peerInput)
	if input == "" {
		return "", ""
	}

	if strings.Contains(input, "://") {
		parsed, err := url.Parse(input)
		if err == nil && parsed.Host != "" {
			return parsed.Host, strings.ToLower(parsed.Scheme)
		}
	}

	return input, ""
}

func legacyAuthorityMatch(leftAuthority, rightAuthority, scheme string) bool {
	left, err := hostport.Normalize(leftAuthority, scheme)
	if err != nil {
		return false
	}
	right, err := hostport.Normalize(rightAuthority, scheme)
	if err != nil {
		return false
	}
	return left == right
}
