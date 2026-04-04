// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package peercompat

import "testing"

func TestBasicAuthDecisionForPeer_MatchedProfileUsesAllowlist(t *testing.T) {
	custom := map[string]*Profile{
		"restricted": {
			Name:                     "restricted",
			AllowedBasicAuthPatterns: []string{"id:token"},
		},
	}
	mappings := []ProfileMapping{
		{Pattern: "peer.example.com", ProfileName: "restricted"},
	}

	contract, err := NewCompiledContract(custom, mappings)
	if err != nil {
		t.Fatalf("NewCompiledContract() unexpected error: %v", err)
	}

	decision := contract.BasicAuthDecisionForPeer("peer.example.com")
	if !decision.Matched {
		t.Fatal("expected mapped peer to be matched")
	}
	if decision.Profile != "restricted" {
		t.Fatalf("expected profile restricted, got %q", decision.Profile)
	}
	if decision.AllowAllPatterns {
		t.Fatal("expected restrictive allowlist, got allow-all")
	}
	if contract.IsBasicAuthPatternAllowedForPeer("peer.example.com", "token:") {
		t.Fatal("expected token: to be denied by restrictive allowlist")
	}
	if !contract.IsBasicAuthPatternAllowedForPeer("peer.example.com", "id:token") {
		t.Fatal("expected id:token to be allowed by restrictive allowlist")
	}
}

func TestBasicAuthDecisionForPeer_UnmatchedPeerUsesStrictDefaults(t *testing.T) {
	contract, err := NewCompiledContract(nil, nil)
	if err != nil {
		t.Fatalf("NewCompiledContract() unexpected error: %v", err)
	}

	decision := contract.BasicAuthDecisionForPeer("unmapped.example.com")
	if decision.Matched {
		t.Fatal("expected unmatched peer to use strict defaults")
	}
	if !decision.AllowAllPatterns {
		t.Fatal("expected strict default to allow all Basic patterns")
	}

	for _, pattern := range []string{"token:", "token:token", ":token", "id:token"} {
		if !contract.IsBasicAuthPatternAllowedForPeer("unmapped.example.com", pattern) {
			t.Fatalf("expected pattern %q to be allowed for strict defaults", pattern)
		}
	}
}

func TestBasicAuthDecisionForPeer_URLInputDoesNotMatchMapping(t *testing.T) {
	custom := map[string]*Profile{
		"restricted": {
			Name:                     "restricted",
			AllowedBasicAuthPatterns: []string{"id:token"},
		},
	}
	mappings := []ProfileMapping{
		{Pattern: "peer.example.com", ProfileName: "restricted"},
	}

	contract, err := NewCompiledContract(custom, mappings)
	if err != nil {
		t.Fatalf("NewCompiledContract() unexpected error: %v", err)
	}

	decision := contract.BasicAuthDecisionForPeer("https://peer.example.com")
	if decision.Matched {
		t.Fatal("expected URL-shaped input to skip matched-peer relaxations")
	}
	if decision.PeerDomain != "" {
		t.Fatalf("expected empty peer domain for URL-shaped input, got %q", decision.PeerDomain)
	}
	if !decision.AllowAllPatterns {
		t.Fatal("expected strict default allow-all for URL-shaped input")
	}
}
