// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package peercompat

// TokenExchangeDecision captures peer-scoped token-exchange compatibility
// behavior used by outbound signing and token fallback consumers.
type TokenExchangeDecision struct {
	PeerDomain       string
	Profile          string
	Matched          bool
	AcceptPlainToken bool
	SendTokenInBody  bool
	GrantType        string
}

// TokenExchangeFallbackDecision is a typed fallback permission keyed by a
// classified failure reason.
type TokenExchangeFallbackDecision struct {
	PeerDomain         string
	Profile            string
	ReasonCode         string
	AllowUnsignedRetry bool
	AllowJSONBodyRetry bool
	Quirk              string
}

// TokenExchangeDecisionForPeer returns compiled token-exchange compatibility
// decisions. Relaxations apply only when a peer mapping matched.
func (c *CompiledContract) TokenExchangeDecisionForPeer(peerDomain string) TokenExchangeDecision {
	domain := signatureDecisionPeerDomain(peerDomain)
	decision := TokenExchangeDecision{
		PeerDomain: domain,
		Profile:    "strict",
		GrantType:  "authorization_code",
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
		decision.AcceptPlainToken = profile.TokenExchange.AcceptPlainToken
		decision.SendTokenInBody = profile.TokenExchange.SendTokenInBody
		decision.GrantType = profile.TokenExchange.GrantType
		return decision
	}

	return decision
}

// TokenExchangeFallbackForReason resolves token retry permissions from the
// peer decision and the classified strict-attempt failure reason.
func (c *CompiledContract) TokenExchangeFallbackForReason(peerDomain, reasonCode string) TokenExchangeFallbackDecision {
	decision := c.TokenExchangeDecisionForPeer(peerDomain)
	fallback := TokenExchangeFallbackDecision{
		PeerDomain: decision.PeerDomain,
		Profile:    decision.Profile,
		ReasonCode: reasonCode,
	}

	switch reasonCode {
	case ReasonSignatureRequired, ReasonSignatureInvalid, ReasonKeyNotFound:
		if decision.AcceptPlainToken {
			fallback.AllowUnsignedRetry = true
			fallback.Quirk = tokenQuirkAcceptPlainToken
		}
	case ReasonTokenExchangeFailed, ReasonProtocolMismatch:
		if decision.SendTokenInBody {
			fallback.AllowJSONBodyRetry = true
			fallback.Quirk = tokenQuirkSendTokenInBody
		}
	}

	return fallback
}
