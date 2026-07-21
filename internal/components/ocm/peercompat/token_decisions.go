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
	matched := c.resolveMatchedPeer(peerDomain)
	decision := TokenExchangeDecision{
		PeerDomain: matched.PeerDomain,
		Profile:    "strict",
		GrantType:  "authorization_code",
	}
	if !matched.Matched {
		return decision
	}

	decision.Profile = matched.Profile.Name
	decision.Matched = true
	decision.AcceptPlainToken = matched.Profile.TokenExchange.AcceptPlainToken
	decision.SendTokenInBody = matched.Profile.TokenExchange.SendTokenInBody
	decision.GrantType = matched.Profile.TokenExchange.GrantType
	return decision
}

// TokenExchangeFallbackForReason resolves token retry permissions from the
// peer decision and the classified strict-attempt failure reason.
//
// Unsigned retry (accept_plain_token) is offered only when a peer mapping
// matched and the compiled profile sets AcceptPlainToken. Unmatched peers
// stay strict. The trigger set (signature_required / signature_invalid /
// key_not_found) covers peers that reject or cannot verify a signed attempt;
// it is not a general "any 4xx" escape hatch. Operators who map a peer into
// such a profile accept that a successful unsigned exchange proves possession
// of the shared secret without HTTP-message integrity on that retry.
func (c *CompiledContract) TokenExchangeFallbackForReason(peerDomain, reasonCode string) TokenExchangeFallbackDecision {
	decision := c.TokenExchangeDecisionForPeer(peerDomain)
	fallback := TokenExchangeFallbackDecision{
		PeerDomain: decision.PeerDomain,
		Profile:    decision.Profile,
		ReasonCode: reasonCode,
	}

	// AcceptPlainToken / SendTokenInBody stay false unless Matched is set.
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
