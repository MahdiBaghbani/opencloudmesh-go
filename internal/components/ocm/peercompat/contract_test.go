// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package peercompat

import (
	"strings"
	"testing"
)

func TestNewCompiledContract_CompilesExplicitUnsignedDiscovery(t *testing.T) {
	custom := map[string]*Profile{
		"peer-a": {
			Name:                   "peer-a",
			AllowUnsignedDiscovery: true,
			TokenExchangeQuirks: []string{
				"accept_plain_token",
				"send_token_in_body",
			},
			TokenExchangeGrantType: "ocm_share",
		},
	}
	mappings := []ProfileMapping{{Pattern: "peer-a.example.com", ProfileName: "peer-a"}}

	contract, err := NewCompiledContract(custom, mappings)
	if err != nil {
		t.Fatalf("NewCompiledContract() unexpected error: %v", err)
	}

	profile, ok := contract.ProfileByName("peer-a")
	if !ok {
		t.Fatal("expected compiled profile peer-a")
	}
	if !profile.Signing.AllowUnsignedDiscovery {
		t.Fatal("expected AllowUnsignedDiscovery to be compiled as explicit field")
	}
	if !profile.TokenExchange.AcceptPlainToken || !profile.TokenExchange.SendTokenInBody {
		t.Fatal("expected token exchange quirks to compile into typed decisions")
	}
	if profile.TokenExchange.GrantType != "ocm_share" {
		t.Fatalf("expected grant type ocm_share, got %q", profile.TokenExchange.GrantType)
	}
}

func TestNewCompiledContract_RejectsRemovedQuirks(t *testing.T) {
	deletedQuirks := []string{
		"skip_" + "digest_validation",
		"allow_" + "keyid_mismatch",
		"allow_" + "unsigned_discovery",
	}
	for _, quirk := range deletedQuirks {
		t.Run(quirk, func(t *testing.T) {
			custom := map[string]*Profile{
				"broken": {
					Name:                "broken",
					TokenExchangeQuirks: []string{quirk},
				},
			}
			_, err := NewCompiledContract(custom, nil)
			if err == nil {
				t.Fatalf("expected unsupported token_exchange_quirk error for %q", quirk)
			}
			if !strings.Contains(err.Error(), "unsupported token_exchange_quirk") {
				t.Fatalf("expected unsupported quirk error, got %v", err)
			}
		})
	}
}

func TestNewCompiledContract_RejectsInvalidGrantType(t *testing.T) {
	custom := map[string]*Profile{
		"broken": {
			Name:                   "broken",
			TokenExchangeGrantType: "invalid_grant",
		},
	}
	_, err := NewCompiledContract(custom, nil)
	if err == nil {
		t.Fatal("expected unsupported token_exchange_grant_type error")
	}
	if !strings.Contains(err.Error(), "unsupported token_exchange_grant_type") {
		t.Fatalf("expected unsupported grant type error, got %v", err)
	}
}
