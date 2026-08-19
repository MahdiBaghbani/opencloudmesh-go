// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package statistics

import (
	"encoding/hex"
	"testing"

	"github.com/zeebo/blake3"
)

func TestHashStatsK_ContextContract(t *testing.T) {
	t.Parallel()

	salt := make([]byte, RedactionSaltSize)
	for i := range salt {
		salt[i] = byte(i + 7)
	}

	got, err := HashStatsK(salt, "run-123")
	if err != nil {
		t.Fatalf("HashStatsK: %v", err)
	}

	// Independent recomputation of keyed-BLAKE3(salt, "stats-session|run-123").
	h, err := blake3.NewKeyed(salt)
	if err != nil {
		t.Fatalf("keyed hasher: %v", err)
	}

	if _, writeErr := h.WriteString("stats-session|run-123"); writeErr != nil {
		t.Fatalf("write context: %v", writeErr)
	}

	want := hex.EncodeToString(h.Sum(nil))
	if got != want {
		t.Fatalf("HashStatsK = %q, want keyed BLAKE3 of stats-session|run-123 = %q", got, want)
	}

	other, err := HashStatsK(salt, "run-456")
	if err != nil {
		t.Fatalf("HashStatsK other: %v", err)
	}

	if got == other {
		t.Fatal("distinct test_run_id values must produce distinct K digests")
	}
}

func TestHashStatsK_RejectsWrongSizeSalt(t *testing.T) {
	t.Parallel()

	if _, err := HashStatsK(nil, "run-123"); err == nil {
		t.Fatal("expected error for empty salt")
	}

	if _, err := HashStatsK([]byte("short"), "run-123"); err == nil {
		t.Fatal("expected error for wrong-size salt")
	}
}
