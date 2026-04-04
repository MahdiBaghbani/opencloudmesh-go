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
		[]ProfileMapping{{Pattern: "*.compat.example", ProfileName: "compat"}},
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
		decision.AllowMismatchedHost || decision.AllowUnsignedDiscovery {
		t.Fatalf("expected strict defaults for unmatched peer: %+v", decision)
	}
}

func TestResolveDiscoveryFailure_GlobalAllowWins(t *testing.T) {
	contract, err := NewCompiledContract(nil, nil)
	if err != nil {
		t.Fatalf("NewCompiledContract() unexpected error: %v", err)
	}

	decision := contract.ResolveDiscoveryFailure("unknown.example", "allow")
	if !decision.Allow {
		t.Fatalf("expected discovery failure allow decision: %+v", decision)
	}
	if decision.ReasonCode != "global_on_discovery_error_allow" {
		t.Fatalf("unexpected reason code: %s", decision.ReasonCode)
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
		[]ProfileMapping{{Pattern: "peer.example", ProfileName: "compat"}},
	)
	if err != nil {
		t.Fatalf("NewCompiledContract() unexpected error: %v", err)
	}

	decision := contract.ResolveDiscoveryFailure("peer.example", "reject")
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
		[]ProfileMapping{{Pattern: "peer.example", ProfileName: "compat"}},
	)
	if err != nil {
		t.Fatalf("NewCompiledContract() unexpected error: %v", err)
	}

	decision := contract.ResolveDiscoveryFailure("other.example", "reject")
	if decision.Allow {
		t.Fatalf("expected unmatched peer to reject discovery failure: %+v", decision)
	}
	if decision.ReasonCode != "discovery_error_reject" {
		t.Fatalf("unexpected reason code: %s", decision.ReasonCode)
	}
}
