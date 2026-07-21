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
// A nil contract (no compiled compatibility contract available to the caller)
// always resolves to the canonical strict profile and HTTPS scheme; it never
// preserves an explicit http:// input scheme. resolveMatchedPeer fails closed
// for a nil receiver, so the nil and non-nil contract cases share one
// resolution path.
func (c *CompiledContract) ResolvePeerOrigin(peerInput string) PeerOriginDecision {
	peerDomain, _ := peerDomainFromInput(peerInput)
	if peerDomain == "" {
		return PeerOriginDecision{}
	}

	profileName := "strict"
	allowHTTP := false
	scheme := "https"

	matched := c.resolveMatchedPeer(peerDomain)
	if matched.Matched {
		profileName = matched.Profile.Name
		allowHTTP = matched.Profile.Transport.AllowHTTP
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
// authority and transport policy. A nil contract resolves through
// ResolvePeerOrigin to the canonical strict/HTTPS profile, so it never allows
// an http:// absoluteURI; it only matches on canonical HTTPS authority or
// fails closed.
func (c *CompiledContract) IsPeerAbsoluteURIAllowed(absoluteURI, peerInput string) bool {
	parsed, err := url.Parse(absoluteURI)
	if err != nil || parsed.Host == "" {
		return false
	}

	uriScheme := strings.ToLower(parsed.Scheme)
	if uriScheme != "http" && uriScheme != "https" {
		return false
	}

	origin := c.ResolvePeerOrigin(peerInput)
	if origin.PeerDomain == "" {
		return false
	}
	if uriScheme == "http" && !origin.AllowHTTP {
		return false
	}

	return authorityMatch(parsed.Host, origin.PeerDomain, uriScheme)
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

func authorityMatch(leftAuthority, rightAuthority, scheme string) bool {
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
