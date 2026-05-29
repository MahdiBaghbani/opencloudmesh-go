// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package peercompat

import "slices"

// BasicAuthDecision captures peer-scoped Basic auth compatibility behavior.
type BasicAuthDecision struct {
	PeerDomain       string
	Profile          string
	Matched          bool
	AllowAllPatterns bool
	AllowedPatterns  []string
}

// IsPatternAllowed checks whether the provided Basic auth pattern is allowed
// by the decision payload.
func (d BasicAuthDecision) IsPatternAllowed(pattern string) bool {
	if d.AllowAllPatterns {
		return true
	}
	for _, allowed := range d.AllowedPatterns {
		if allowed == pattern {
			return true
		}
	}
	return false
}

// BasicAuthDecisionForPeer returns peer-scoped Basic auth compatibility
// decisions. Pattern restrictions apply only when a peer mapping matched.
func (c *CompiledContract) BasicAuthDecisionForPeer(peerDomain string) BasicAuthDecision {
	domain := signatureDecisionPeerDomain(peerDomain)
	decision := BasicAuthDecision{
		PeerDomain:       domain,
		Profile:          "strict",
		AllowAllPatterns: true,
	}
	if domain == "" || c == nil || c.registry == nil {
		return decision
	}

	for _, mapping := range c.registry.mappings {
		if !matchPattern(mapping.Pattern, domain) {
			continue
		}
		profile, ok := c.profiles[mapping.Profile]
		if !ok {
			return decision
		}
		decision.Profile = profile.Name
		decision.Matched = true
		decision.AllowAllPatterns = profile.BasicAuth.AllowAllPatterns
		decision.AllowedPatterns = slices.Clone(profile.BasicAuth.AllowedPatterns)
		return decision
	}

	return decision
}

// IsBasicAuthPatternAllowedForPeer reports whether a Basic auth pattern is
// allowed for the resolved peer compatibility profile.
func (c *CompiledContract) IsBasicAuthPatternAllowedForPeer(peerDomain, pattern string) bool {
	return c.BasicAuthDecisionForPeer(peerDomain).IsPatternAllowed(pattern)
}
