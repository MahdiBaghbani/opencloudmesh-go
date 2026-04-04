// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package peercompat

import "testing"

func TestCompatibilityDecisionLogSlogAttrs_WithOptionalFields(t *testing.T) {
	entry := CompatibilityDecisionLog{
		RequestID:          "req-123",
		PeerDomain:         "peer.example.com",
		Profile:            "nextcloud",
		Operation:          "outbound_signing",
		Decision:           "allow_unsigned",
		ReasonCode:         "compat_override",
		CompatibilityScope: "peer-profile-relaxations",
		Quirk:              "accept_plain_token",
	}

	keys := attrKeys(entry.SlogAttrs())
	want := []string{
		"request_id",
		"peer_domain",
		"profile",
		"operation",
		"decision",
		"reason_code",
		"compatibility_scope",
		"quirk",
	}
	assertEqualKeys(t, keys, want)
}

func TestCompatibilityDecisionLogSlogAttrs_WithoutOptionalFields(t *testing.T) {
	entry := CompatibilityDecisionLog{
		PeerDomain:         "peer.example.com",
		Profile:            "strict",
		Operation:          "inbound_signature",
		Decision:           "require_signature",
		ReasonCode:         "peer_requires_signatures",
		CompatibilityScope: "none",
	}

	keys := attrKeys(entry.SlogAttrs())
	want := []string{
		"peer_domain",
		"profile",
		"operation",
		"decision",
		"reason_code",
		"compatibility_scope",
	}
	assertEqualKeys(t, keys, want)
}

func attrKeys(attrs []any) []string {
	keys := make([]string, 0, len(attrs)/2)
	for idx := 0; idx+1 < len(attrs); idx += 2 {
		key, ok := attrs[idx].(string)
		if !ok {
			continue
		}
		keys = append(keys, key)
	}
	return keys
}

func assertEqualKeys(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d keys %v, want %d keys %v", len(got), got, len(want), want)
	}
	for idx := range want {
		if got[idx] != want[idx] {
			t.Fatalf("key[%d] = %q, want %q (all keys: %v)", idx, got[idx], want[idx], got)
		}
	}
}
