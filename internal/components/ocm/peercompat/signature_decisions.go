// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package peercompat

// SignaturePeerDecision captures peer-scoped compatibility decisions used by
// signature-capability call sites.
type SignaturePeerDecision struct {
	PeerDomain             string
	Profile                string
	Matched                bool
	AllowUnsignedInbound   bool
	AllowUnsignedOutbound  bool
	AllowMismatchedHost    bool
	AllowUnsignedDiscovery bool
}

// DiscoveryFailureDecision resolves whether discovery errors may fail open.
// Discovery fail-open is granted only to matched peers with
// allow_unsigned_discovery.
type DiscoveryFailureDecision struct {
	PeerDomain string
	Profile    string
	Allow      bool
	ReasonCode string
}

// SignatureDecisionForPeer returns peer-scoped signature compatibility
// decisions. Relaxations apply only when a peer mapping matched.
func (c *CompiledContract) SignatureDecisionForPeer(peerDomain string) SignaturePeerDecision {
	matched := c.resolveMatchedPeer(peerDomain)
	decision := SignaturePeerDecision{
		PeerDomain: matched.PeerDomain,
		Profile:    "strict",
	}
	if !matched.Matched {
		return decision
	}

	decision.Profile = matched.Profile.Name
	decision.Matched = true
	decision.AllowUnsignedInbound = matched.Profile.Signing.AllowUnsignedInbound
	decision.AllowUnsignedOutbound = matched.Profile.Signing.AllowUnsignedOutbound
	decision.AllowMismatchedHost = matched.Profile.Signing.AllowMismatchedHost
	decision.AllowUnsignedDiscovery = matched.Profile.Signing.AllowUnsignedDiscovery
	return decision
}

func signatureDecisionPeerDomain(peerInput string) string {
	domain, inputScheme := peerDomainFromInput(peerInput)
	if inputScheme != "" {
		return ""
	}
	return normalizeDomain(domain)
}

// ResolveDiscoveryFailure decides whether discovery errors can fail open.
// Only matched peers with allow_unsigned_discovery may fail open.
func (c *CompiledContract) ResolveDiscoveryFailure(peerDomain string) DiscoveryFailureDecision {
	peerDecision := c.SignatureDecisionForPeer(peerDomain)
	decision := DiscoveryFailureDecision{
		PeerDomain: peerDecision.PeerDomain,
		Profile:    peerDecision.Profile,
		Allow:      false,
		ReasonCode: "discovery_error_reject",
	}

	if peerDecision.Matched && peerDecision.AllowUnsignedDiscovery {
		decision.Allow = true
		decision.ReasonCode = "peer_allow_unsigned_discovery"
		return decision
	}

	return decision
}
