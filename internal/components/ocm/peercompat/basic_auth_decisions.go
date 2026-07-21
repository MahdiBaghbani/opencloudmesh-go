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
	matched := c.resolveMatchedPeer(peerDomain)
	decision := BasicAuthDecision{
		PeerDomain:       matched.PeerDomain,
		Profile:          "strict",
		AllowAllPatterns: true,
	}
	if !matched.Matched {
		return decision
	}

	decision.Profile = matched.Profile.Name
	decision.Matched = true
	decision.AllowAllPatterns = matched.Profile.BasicAuth.AllowAllPatterns
	decision.AllowedPatterns = slices.Clone(matched.Profile.BasicAuth.AllowedPatterns)
	return decision
}

// IsBasicAuthPatternAllowedForPeer reports whether a Basic auth pattern is
// allowed for the resolved peer compatibility profile.
func (c *CompiledContract) IsBasicAuthPatternAllowedForPeer(peerDomain, pattern string) bool {
	return c.BasicAuthDecisionForPeer(peerDomain).IsPatternAllowed(pattern)
}
