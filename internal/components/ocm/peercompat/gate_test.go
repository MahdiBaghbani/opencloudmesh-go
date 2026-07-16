// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package peercompat

import "testing"

// matchedPeerProfile builds a profile with every relaxation enabled, so any
// leakage through the gate is observable as a non-strict decision field.
func matchedPeerProfile() *Profile {
	return &Profile{
		Name:                           "compat",
		AllowUnsignedInbound:           true,
		AllowUnsignedOutbound:          true,
		AllowMismatchedHost:            true,
		AllowUnsignedDiscovery:         true,
		AcceptLegacyDiscoveryPublicKey: true,
		TokenExchangeQuirks:            []string{"accept_plain_token", "send_token_in_body"},
		TokenExchangeGrantType:         "ocm_share",
		AllowedBasicAuthPatterns:       []string{"token:"},
	}
}

func matchedPeerMappings() []ProfileMapping {
	return []ProfileMapping{{Pattern: "peer.example", Profile: "compat"}}
}

// assertStrictSignatureDecision verifies a signature decision failed closed:
// unmatched, strict profile, and no relaxation fields copied.
func assertStrictSignatureDecision(t *testing.T, decision SignaturePeerDecision) {
	t.Helper()
	if decision.Matched {
		t.Fatalf("expected Matched=false, got true: %+v", decision)
	}
	if decision.Profile != "strict" {
		t.Fatalf("expected Profile=strict, got %q", decision.Profile)
	}
	if decision.AllowUnsignedInbound || decision.AllowUnsignedOutbound ||
		decision.AllowMismatchedHost || decision.AllowUnsignedDiscovery ||
		decision.AcceptLegacyDiscoveryPublicKey {
		t.Fatalf("expected no signature relaxations on closed gate: %+v", decision)
	}
}

func assertStrictTokenDecision(t *testing.T, decision TokenExchangeDecision) {
	t.Helper()
	if decision.Matched {
		t.Fatalf("expected Matched=false, got true: %+v", decision)
	}
	if decision.Profile != "strict" {
		t.Fatalf("expected Profile=strict, got %q", decision.Profile)
	}
	if decision.AcceptPlainToken || decision.SendTokenInBody {
		t.Fatalf("expected no token relaxations on closed gate: %+v", decision)
	}
	if decision.GrantType != "authorization_code" {
		t.Fatalf("expected default grant type, got %q", decision.GrantType)
	}
}

// assertStrictBasicAuthDecision verifies a Basic auth decision failed closed:
// unmatched, strict profile, allow-all patterns, and no allowlist copied.
func assertStrictBasicAuthDecision(t *testing.T, decision BasicAuthDecision) {
	t.Helper()
	if decision.Matched {
		t.Fatalf("expected Matched=false, got true: %+v", decision)
	}
	if decision.Profile != "strict" {
		t.Fatalf("expected Profile=strict, got %q", decision.Profile)
	}
	if !decision.AllowAllPatterns {
		t.Fatalf("expected AllowAllPatterns=true on closed gate: %+v", decision)
	}
	if len(decision.AllowedPatterns) != 0 {
		t.Fatalf("expected no AllowedPatterns copied from relaxing profile: %+v", decision)
	}
}

func TestGate_EmptyPeerFailsClosed(t *testing.T) {
	contract, err := NewCompiledContract(
		map[string]*Profile{"compat": matchedPeerProfile()},
		matchedPeerMappings(),
	)
	if err != nil {
		t.Fatalf("NewCompiledContract() unexpected error: %v", err)
	}

	assertStrictSignatureDecision(t, contract.SignatureDecisionForPeer(""))
	assertStrictTokenDecision(t, contract.TokenExchangeDecisionForPeer(""))
	assertStrictBasicAuthDecision(t, contract.BasicAuthDecisionForPeer(""))
}

func TestGate_NilContractFailsClosed(t *testing.T) {
	var contract *CompiledContract

	decision := contract.SignatureDecisionForPeer("peer.example")
	if decision.Matched {
		t.Fatalf("expected nil contract to fail closed: %+v", decision)
	}
	if decision.Profile != "strict" {
		t.Fatalf("expected Profile=strict, got %q", decision.Profile)
	}

	tokenDecision := contract.TokenExchangeDecisionForPeer("peer.example")
	if tokenDecision.Matched {
		t.Fatalf("expected nil contract to fail closed: %+v", tokenDecision)
	}

	assertStrictBasicAuthDecision(t, contract.BasicAuthDecisionForPeer("peer.example"))
}

func TestGate_NilRegistryFailsClosed(t *testing.T) {
	contract := &CompiledContract{scope: CompatibilityScopeScoped}

	decision := contract.SignatureDecisionForPeer("peer.example")
	if decision.Matched {
		t.Fatalf("expected nil registry to fail closed: %+v", decision)
	}
	if decision.Profile != "strict" {
		t.Fatalf("expected Profile=strict, got %q", decision.Profile)
	}

	assertStrictBasicAuthDecision(t, contract.BasicAuthDecisionForPeer("peer.example"))
}

func TestGate_UnknownScopeFailsClosed(t *testing.T) {
	registry := NewProfileRegistry(
		map[string]*Profile{"compat": matchedPeerProfile()},
		matchedPeerMappings(),
	)
	contract, err := BuildCompiledContractFromRegistryWithScope(
		registry,
		CompatibilityScope("bogus"),
	)
	if err != nil {
		t.Fatalf("BuildCompiledContractFromRegistryWithScope() unexpected error: %v", err)
	}

	// The peer maps to a fully relaxing profile, but an unknown scope must keep
	// the gate closed across signature, token, and Basic Auth decisions.
	assertStrictSignatureDecision(t, contract.SignatureDecisionForPeer("peer.example"))
	assertStrictTokenDecision(t, contract.TokenExchangeDecisionForPeer("peer.example"))
	assertStrictBasicAuthDecision(t, contract.BasicAuthDecisionForPeer("peer.example"))

	legacy := contract.LegacyDiscoveryPublicKeyDecisionForPeer("peer.example")
	if legacy.Allow {
		t.Fatalf("expected unknown scope to reject legacy discovery: %+v", legacy)
	}
	if legacy.ReasonCode != "legacy_discovery_public_key_reject" {
		t.Fatalf("unexpected reason code: %s", legacy.ReasonCode)
	}

	discovery := contract.ResolveDiscoveryFailure("peer.example")
	if discovery.Allow {
		t.Fatalf("expected unknown scope to reject discovery failure: %+v", discovery)
	}
	if discovery.ReasonCode != "discovery_error_reject" {
		t.Fatalf("unexpected reason code: %s", discovery.ReasonCode)
	}
}

func TestGate_NoneScopeFailsClosed(t *testing.T) {
	registry := NewProfileRegistry(
		map[string]*Profile{"compat": matchedPeerProfile()},
		matchedPeerMappings(),
	)
	contract, err := BuildCompiledContractFromRegistryWithScope(
		registry,
		CompatibilityScopeNone,
	)
	if err != nil {
		t.Fatalf("BuildCompiledContractFromRegistryWithScope() unexpected error: %v", err)
	}

	assertStrictSignatureDecision(t, contract.SignatureDecisionForPeer("peer.example"))
	assertStrictTokenDecision(t, contract.TokenExchangeDecisionForPeer("peer.example"))
	assertStrictBasicAuthDecision(t, contract.BasicAuthDecisionForPeer("peer.example"))
}

func TestGate_UnmatchedPeerRetainsStrictMatchedFalse(t *testing.T) {
	contract, err := NewCompiledContract(
		map[string]*Profile{"compat": matchedPeerProfile()},
		matchedPeerMappings(),
	)
	if err != nil {
		t.Fatalf("NewCompiledContract() unexpected error: %v", err)
	}

	// peer.example maps to compat, other.example does not.
	assertStrictSignatureDecision(t, contract.SignatureDecisionForPeer("other.example"))
	assertStrictTokenDecision(t, contract.TokenExchangeDecisionForPeer("other.example"))
	assertStrictBasicAuthDecision(t, contract.BasicAuthDecisionForPeer("other.example"))
}

func TestGate_MatchedScopedPeerAppliesRelaxations(t *testing.T) {
	contract, err := NewCompiledContract(
		map[string]*Profile{"compat": matchedPeerProfile()},
		matchedPeerMappings(),
	)
	if err != nil {
		t.Fatalf("NewCompiledContract() unexpected error: %v", err)
	}

	sig := contract.SignatureDecisionForPeer("peer.example")
	if !sig.Matched {
		t.Fatalf("expected matched peer: %+v", sig)
	}
	if sig.Profile != "compat" {
		t.Fatalf("expected Profile=compat, got %q", sig.Profile)
	}
	if !sig.AllowUnsignedInbound || !sig.AllowUnsignedOutbound ||
		!sig.AllowMismatchedHost || !sig.AllowUnsignedDiscovery ||
		!sig.AcceptLegacyDiscoveryPublicKey {
		t.Fatalf("expected all signature relaxations applied: %+v", sig)
	}

	token := contract.TokenExchangeDecisionForPeer("peer.example")
	if !token.Matched {
		t.Fatalf("expected matched token decision: %+v", token)
	}
	if !token.AcceptPlainToken || !token.SendTokenInBody {
		t.Fatalf("expected token quirks applied: %+v", token)
	}
	if token.GrantType != "ocm_share" {
		t.Fatalf("expected grant type ocm_share, got %q", token.GrantType)
	}

	basicAuth := contract.BasicAuthDecisionForPeer("peer.example")
	if !basicAuth.Matched {
		t.Fatalf("expected matched Basic auth decision: %+v", basicAuth)
	}
	if basicAuth.Profile != "compat" {
		t.Fatalf("expected Profile=compat, got %q", basicAuth.Profile)
	}
	if basicAuth.AllowAllPatterns {
		t.Fatalf("expected restrictive Basic auth allowlist: %+v", basicAuth)
	}
	if len(basicAuth.AllowedPatterns) != 1 || basicAuth.AllowedPatterns[0] != "token:" {
		t.Fatalf("expected AllowedPatterns=[token:], got %+v", basicAuth.AllowedPatterns)
	}
}
