// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package peercompat

import "strings"

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

// DiscoveryFailureDecision resolves unsigned-discovery behavior from global and
// peer-scoped settings.
type DiscoveryFailureDecision struct {
	PeerDomain string
	Profile    string
	Allow      bool
	ReasonCode string
}

// SignatureDecisionForPeer returns peer-scoped signature compatibility
// decisions. Relaxations apply only when a peer mapping matched.
func (c *CompiledContract) SignatureDecisionForPeer(peerDomain string) SignaturePeerDecision {
	domain := signatureDecisionPeerDomain(peerDomain)
	decision := SignaturePeerDecision{
		PeerDomain: domain,
		Profile:    "strict",
	}
	if domain == "" || c == nil || c.registry == nil {
		return decision
	}

	for _, mapping := range c.registry.mappings {
		if !matchPattern(mapping.Pattern, domain) {
			continue
		}
		profile, ok := c.profiles[mapping.ProfileName]
		if !ok {
			return decision
		}
		decision.Profile = profile.Name
		decision.Matched = true
		decision.AllowUnsignedInbound = profile.Signing.AllowUnsignedInbound
		decision.AllowUnsignedOutbound = profile.Signing.AllowUnsignedOutbound
		decision.AllowMismatchedHost = profile.Signing.AllowMismatchedHost
		decision.AllowUnsignedDiscovery = profile.Signing.AllowUnsignedDiscovery
		return decision
	}

	return decision
}

func signatureDecisionPeerDomain(peerInput string) string {
	domain, inputScheme := peerDomainFromInput(peerInput)
	if inputScheme != "" {
		return ""
	}
	return normalizeDomain(domain)
}

// ResolveDiscoveryFailure decides whether discovery errors can fail open. Global
// allow takes precedence; otherwise only matched peers with
// allow_unsigned_discovery may fail open.
func (c *CompiledContract) ResolveDiscoveryFailure(peerDomain string, onDiscoveryError string) DiscoveryFailureDecision {
	peerDecision := c.SignatureDecisionForPeer(peerDomain)
	decision := DiscoveryFailureDecision{
		PeerDomain: peerDecision.PeerDomain,
		Profile:    peerDecision.Profile,
		Allow:      false,
		ReasonCode: "discovery_error_reject",
	}

	if strings.EqualFold(onDiscoveryError, "allow") {
		decision.Allow = true
		decision.ReasonCode = "global_on_discovery_error_allow"
		return decision
	}

	if peerDecision.Matched && peerDecision.AllowUnsignedDiscovery {
		decision.Allow = true
		decision.ReasonCode = "peer_allow_unsigned_discovery"
		return decision
	}

	return decision
}
