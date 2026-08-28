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

func TestHashStatsHost_RejectsEmptySalt(t *testing.T) {
	t.Parallel()

	if _, err := HashStatsHost(nil, "example.com"); err == nil {
		t.Fatal("expected error for empty salt")
	}
}

func TestHashStatsHost_RejectsWrongSizeSalt(t *testing.T) {
	t.Parallel()

	if _, err := HashStatsHost([]byte("short"), "example.com"); err == nil {
		t.Fatal("expected error for wrong-size salt")
	}
}

func TestHashRedactSig_RejectsEmptySalt(t *testing.T) {
	t.Parallel()

	if _, err := HashRedactSig(nil, []byte("token")); err == nil {
		t.Fatal("expected error for empty salt")
	}
}

func TestHashRedactSig_RejectsWrongSizeSalt(t *testing.T) {
	t.Parallel()

	if _, err := HashRedactSig([]byte("short"), []byte("token")); err == nil {
		t.Fatal("expected error for wrong-size salt")
	}
}

func TestHashStatsHostAndRedactSig(t *testing.T) {
	t.Parallel()

	salt := make([]byte, RedactionSaltSize)
	for i := range salt {
		salt[i] = byte(i)
	}

	hostHash, err := HashStatsHost(salt, "Example.COM")
	if err != nil {
		t.Fatalf("HashStatsHost: %v", err)
	}

	hostHash2, err := HashStatsHost(salt, "example.com")
	if err != nil {
		t.Fatalf("HashStatsHost lowercase: %v", err)
	}

	if hostHash != hostHash2 {
		t.Fatalf("host hash mismatch: %q vs %q", hostHash, hostHash2)
	}

	sigHash, err := HashRedactSig(salt, []byte("token-value"))
	if err != nil {
		t.Fatalf("HashRedactSig: %v", err)
	}

	if len(sigHash) != RedactionSaltSize {
		t.Fatalf("sig hash len = %d, want %d", len(sigHash), RedactionSaltSize)
	}
}

func TestHashContextsDoNotCollideForSameInput(t *testing.T) {
	t.Parallel()

	salt := make([]byte, RedactionSaltSize)
	for i := range salt {
		salt[i] = byte(i + 3)
	}

	input := []byte("shared-logical-input")

	hostHash, err := HashStatsHost(salt, string(input))
	if err != nil {
		t.Fatalf("HashStatsHost: %v", err)
	}

	hostHashAgain, err := HashStatsHost(salt, string(input))
	if err != nil {
		t.Fatalf("HashStatsHost repeat: %v", err)
	}

	if hostHash != hostHashAgain {
		t.Fatal("stats-host hash must be stable for the same input")
	}

	sigHash, err := HashRedactSig(salt, input)
	if err != nil {
		t.Fatalf("HashRedactSig: %v", err)
	}

	sigHashAgain, err := HashRedactSig(salt, input)
	if err != nil {
		t.Fatalf("HashRedactSig repeat: %v", err)
	}

	if string(sigHash) != string(sigHashAgain) {
		t.Fatal("redact-sig hash must be stable for the same input")
	}

	sigHashHex := hex.EncodeToString(sigHash)
	if hostHash == sigHashHex {
		t.Fatal("stats-host and redact-sig hashes must not collide for the same input")
	}
}
