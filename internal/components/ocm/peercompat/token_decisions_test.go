// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package peercompat

import "testing"

func TestTokenExchangeDecisionForPeer_MatchedProfile(t *testing.T) {
	contract, err := NewCompiledContract(
		map[string]*Profile{
			"nextcloud-like": {
				Name:                   "nextcloud-like",
				TokenExchangeQuirks:    []string{"accept_plain_token", "send_token_in_body"},
				TokenExchangeGrantType: "ocm_share",
			},
		},
		[]ProfileMapping{
			{Pattern: "peer.example", Profile: "nextcloud-like"},
		},
	)
	if err != nil {
		t.Fatalf("NewCompiledContract() unexpected error: %v", err)
	}

	decision := contract.TokenExchangeDecisionForPeer("peer.example")
	if !decision.Matched {
		t.Fatalf("expected matched token decision: %+v", decision)
	}
	if !decision.AcceptPlainToken || !decision.SendTokenInBody {
		t.Fatalf("expected token quirks from compiled profile: %+v", decision)
	}
	if decision.GrantType != "ocm_share" {
		t.Fatalf("expected grant type ocm_share, got %q", decision.GrantType)
	}
}

func TestTokenExchangeDecisionForPeer_UnmatchedUsesStrictDefaults(t *testing.T) {
	contract, err := NewCompiledContract(nil, nil)
	if err != nil {
		t.Fatalf("NewCompiledContract() unexpected error: %v", err)
	}

	decision := contract.TokenExchangeDecisionForPeer("unknown.example")
	if decision.Matched {
		t.Fatalf("expected unmatched decision: %+v", decision)
	}
	if decision.Profile != "strict" {
		t.Fatalf("expected strict profile default, got %q", decision.Profile)
	}
	if decision.AcceptPlainToken || decision.SendTokenInBody {
		t.Fatalf("expected strict defaults without token quirks: %+v", decision)
	}
	if decision.GrantType != "authorization_code" {
		t.Fatalf("expected authorization_code default grant, got %q", decision.GrantType)
	}
}

func TestTokenExchangeDecisionForPeer_URLShapedInputDoesNotMatch(t *testing.T) {
	contract, err := NewCompiledContract(
		map[string]*Profile{
			"compat": {
				Name:                "compat",
				TokenExchangeQuirks: []string{"accept_plain_token"},
			},
		},
		[]ProfileMapping{
			{Pattern: "peer.example", Profile: "compat"},
		},
	)
	if err != nil {
		t.Fatalf("NewCompiledContract() unexpected error: %v", err)
	}

	decision := contract.TokenExchangeDecisionForPeer("https://peer.example")
	if decision.Matched {
		t.Fatalf("expected URL-shaped input to stay unmatched: %+v", decision)
	}
}

func TestTokenExchangeFallbackForReason_AcceptPlainToken(t *testing.T) {
	contract, err := NewCompiledContract(
		map[string]*Profile{
			"compat": {
				Name:                "compat",
				TokenExchangeQuirks: []string{"accept_plain_token"},
			},
		},
		[]ProfileMapping{
			{Pattern: "peer.example", Profile: "compat"},
		},
	)
	if err != nil {
		t.Fatalf("NewCompiledContract() unexpected error: %v", err)
	}

	fallback := contract.TokenExchangeFallbackForReason("peer.example", ReasonSignatureInvalid)
	if !fallback.AllowUnsignedRetry {
		t.Fatalf("expected unsigned retry for accept_plain_token: %+v", fallback)
	}
	if fallback.Quirk != "accept_plain_token" {
		t.Fatalf("expected accept_plain_token quirk, got %q", fallback.Quirk)
	}
}

func TestTokenExchangeFallbackForReason_SendTokenInBody(t *testing.T) {
	contract, err := NewCompiledContract(
		map[string]*Profile{
			"compat": {
				Name:                "compat",
				TokenExchangeQuirks: []string{"send_token_in_body"},
			},
		},
		[]ProfileMapping{
			{Pattern: "peer.example", Profile: "compat"},
		},
	)
	if err != nil {
		t.Fatalf("NewCompiledContract() unexpected error: %v", err)
	}

	fallback := contract.TokenExchangeFallbackForReason("peer.example", ReasonProtocolMismatch)
	if !fallback.AllowJSONBodyRetry {
		t.Fatalf("expected JSON-body retry for send_token_in_body: %+v", fallback)
	}
	if fallback.Quirk != "send_token_in_body" {
		t.Fatalf("expected send_token_in_body quirk, got %q", fallback.Quirk)
	}
}
