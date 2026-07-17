// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package peercompat

import "testing"

func TestSignatureDecisionForPeer_MatchedProfile(t *testing.T) {
	contract, err := NewCompiledContract(
		map[string]*Profile{
			"compat": {
				Name:                   "compat",
				AllowUnsignedInbound:   true,
				AllowUnsignedOutbound:  true,
				AllowMismatchedHost:    true,
				AllowUnsignedDiscovery: true,
			},
		},
		[]ProfileMapping{{Pattern: "*.compat.example", Profile: "compat"}},
	)
	if err != nil {
		t.Fatalf("NewCompiledContract() unexpected error: %v", err)
	}

	decision := contract.SignatureDecisionForPeer("node.compat.example")
	if !decision.Matched {
		t.Fatal("expected peer mapping match")
	}
	if decision.Profile != "compat" {
		t.Fatalf("expected profile compat, got %q", decision.Profile)
	}
	if !decision.AllowUnsignedInbound || !decision.AllowUnsignedOutbound ||
		!decision.AllowMismatchedHost || !decision.AllowUnsignedDiscovery {
		t.Fatalf("expected all relaxations enabled for matched profile: %+v", decision)
	}
}

func TestSignatureDecisionForPeer_UnmatchedUsesStrictDefaults(t *testing.T) {
	contract, err := NewCompiledContract(nil, nil)
	if err != nil {
		t.Fatalf("NewCompiledContract() unexpected error: %v", err)
	}

	decision := contract.SignatureDecisionForPeer("unknown.example")
	if decision.Matched {
		t.Fatal("expected unmatched peer")
	}
	if decision.Profile != "strict" {
		t.Fatalf("expected strict profile fallback, got %q", decision.Profile)
	}
	if decision.AllowUnsignedInbound || decision.AllowUnsignedOutbound ||
		decision.AllowMismatchedHost || decision.AllowUnsignedDiscovery ||
		decision.AllowLegacyProtocolName {
		t.Fatalf("expected strict defaults for unmatched peer: %+v", decision)
	}
}

func TestSignatureDecisionForPeer_AllowLegacyProtocolNameOnlyWhenMatched(t *testing.T) {
	contract, err := NewCompiledContract(
		map[string]*Profile{
			"legacy-protocol": {
				Name:                    "legacy-protocol",
				AllowLegacyProtocolName: true,
			},
		},
		[]ProfileMapping{{Pattern: "*.legacy.example", Profile: "legacy-protocol"}},
	)
	if err != nil {
		t.Fatalf("NewCompiledContract() unexpected error: %v", err)
	}

	decision := contract.SignatureDecisionForPeer("node.legacy.example")
	if !decision.Matched {
		t.Fatal("expected peer mapping match")
	}
	if !decision.AllowLegacyProtocolName {
		t.Fatal("expected AllowLegacyProtocolName=true for matched profile")
	}
	if decision.AllowUnsignedInbound || decision.AllowUnsignedOutbound ||
		decision.AllowMismatchedHost || decision.AllowUnsignedDiscovery {
		t.Fatalf("expected only protocol-name relaxation: %+v", decision)
	}
}

func TestSignatureDecisionForPeer_NoneScopeBlocksLegacyProtocolName(t *testing.T) {
	registry := NewProfileRegistry(
		map[string]*Profile{
			"legacy-protocol": {
				Name:                    "legacy-protocol",
				AllowLegacyProtocolName: true,
			},
		},
		[]ProfileMapping{{Pattern: "*.legacy.example", Profile: "legacy-protocol"}},
	)
	contract, err := BuildCompiledContractFromRegistryWithScope(registry, CompatibilityScopeNone)
	if err != nil {
		t.Fatalf("BuildCompiledContractFromRegistryWithScope() unexpected error: %v", err)
	}

	decision := contract.SignatureDecisionForPeer("node.legacy.example")
	if decision.Matched {
		t.Fatal("expected closed compatibility scope to block matched-peer relaxations")
	}
	if decision.AllowLegacyProtocolName {
		t.Fatalf("expected AllowLegacyProtocolName=false under none scope: %+v", decision)
	}
}

func TestCompileProfile_AllowLegacyProtocolNameCountsAsRelaxation(t *testing.T) {
	compiled, err := compileProfile(&Profile{
		Name:                    "legacy-protocol",
		AllowLegacyProtocolName: true,
	})
	if err != nil {
		t.Fatalf("compileProfile() unexpected error: %v", err)
	}
	summary := summarizeProfile(compiled)
	if !summary.HasRelaxations {
		t.Fatal("expected AllowLegacyProtocolName to count as a profile relaxation")
	}
}

func TestSignatureDecisionForPeer_URLShapedInputDoesNotMatch(t *testing.T) {
	contract, err := NewCompiledContract(
		map[string]*Profile{
			"compat": {
				Name:                 "compat",
				AllowUnsignedInbound: true,
			},
		},
		[]ProfileMapping{{Pattern: "peer.example", Profile: "compat"}},
	)
	if err != nil {
		t.Fatalf("NewCompiledContract() unexpected error: %v", err)
	}

	decision := contract.SignatureDecisionForPeer("https://peer.example")
	if decision.Matched {
		t.Fatalf("expected URL-shaped input to stay unmatched: %+v", decision)
	}
	if decision.PeerDomain != "" {
		t.Fatalf("expected empty peer domain for invalid input, got %q", decision.PeerDomain)
	}
	if decision.Profile != "strict" {
		t.Fatalf("expected strict profile fallback, got %q", decision.Profile)
	}
}

func TestResolveDiscoveryFailure_MatchedPeerCanFailOpen(t *testing.T) {
	contract, err := NewCompiledContract(
		map[string]*Profile{
			"compat": {
				Name:                   "compat",
				AllowUnsignedDiscovery: true,
			},
		},
		[]ProfileMapping{{Pattern: "peer.example", Profile: "compat"}},
	)
	if err != nil {
		t.Fatalf("NewCompiledContract() unexpected error: %v", err)
	}

	decision := contract.ResolveDiscoveryFailure("peer.example")
	if !decision.Allow {
		t.Fatalf("expected matched peer to fail open: %+v", decision)
	}
	if decision.ReasonCode != "peer_allow_unsigned_discovery" {
		t.Fatalf("unexpected reason code: %s", decision.ReasonCode)
	}
}

func TestResolveDiscoveryFailure_UnmatchedPeerRejects(t *testing.T) {
	contract, err := NewCompiledContract(
		map[string]*Profile{
			"compat": {
				Name:                   "compat",
				AllowUnsignedDiscovery: true,
			},
		},
		[]ProfileMapping{{Pattern: "peer.example", Profile: "compat"}},
	)
	if err != nil {
		t.Fatalf("NewCompiledContract() unexpected error: %v", err)
	}

	decision := contract.ResolveDiscoveryFailure("other.example")
	if decision.Allow {
		t.Fatalf("expected unmatched peer to reject discovery failure: %+v", decision)
	}
	if decision.ReasonCode != "discovery_error_reject" {
		t.Fatalf("unexpected reason code: %s", decision.ReasonCode)
	}
}
