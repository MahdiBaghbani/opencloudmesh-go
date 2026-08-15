// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package core

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/statistics"
)

func TestCore_StatsSaltAndHashHost(t *testing.T) {
	t.Parallel()

	salt := make([]byte, statistics.RedactionSaltSize)
	for i := range salt {
		salt[i] = byte(i + 1)
	}

	c, err := New(salt)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	gotSalt := c.StatsSalt()
	if len(gotSalt) != statistics.RedactionSaltSize {
		t.Fatalf("StatsSalt len = %d, want %d", len(gotSalt), statistics.RedactionSaltSize)
	}

	hash, err := c.HashHost("Peer.Example")
	if err != nil {
		t.Fatalf("HashHost: %v", err)
	}

	if hash == "" {
		t.Fatal("expected non-empty host hash")
	}
}

func TestNew_RejectsEmptySalt(t *testing.T) {
	t.Parallel()

	if _, err := New(nil); err == nil {
		t.Fatal("expected error for empty salt")
	}
}

func TestNew_RejectsWrongSizeSalt(t *testing.T) {
	t.Parallel()

	if _, err := New([]byte("too-short")); err == nil {
		t.Fatal("expected error for wrong-size salt")
	}
}

func TestCore_HashHostDeterministic(t *testing.T) {
	t.Parallel()

	salt := make([]byte, statistics.RedactionSaltSize)
	for i := range salt {
		salt[i] = byte(i + 1)
	}

	c, err := New(salt)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	first, err := c.HashHost("peer.example")
	if err != nil {
		t.Fatalf("HashHost first: %v", err)
	}

	second, err := c.HashHost("peer.example")
	if err != nil {
		t.Fatalf("HashHost second: %v", err)
	}

	if first != second {
		t.Fatalf("HashHost not deterministic: %q vs %q", first, second)
	}

	mixedCase, err := c.HashHost("Peer.Example")
	if err != nil {
		t.Fatalf("HashHost mixed case: %v", err)
	}

	if mixedCase != first {
		t.Fatalf("HashHost lowercase mismatch: %q vs %q", mixedCase, first)
	}
}

func TestCore_CopyIsolation(t *testing.T) {
	t.Parallel()

	salt := make([]byte, statistics.RedactionSaltSize)
	for i := range salt {
		salt[i] = byte(i + 1)
	}

	c, err := New(salt)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	baselineHash, err := c.HashHost("peer.example")
	if err != nil {
		t.Fatalf("HashHost baseline: %v", err)
	}

	baselineSalt := c.StatsSalt()

	for i := range salt {
		salt[i] = 0
	}

	gotSalt := c.StatsSalt()
	for i := range gotSalt {
		gotSalt[i] = 0
	}

	afterHash, err := c.HashHost("peer.example")
	if err != nil {
		t.Fatalf("HashHost after mutation: %v", err)
	}

	if afterHash != baselineHash {
		t.Fatalf("HashHost changed after salt mutation: %q vs %q", afterHash, baselineHash)
	}

	afterSalt := c.StatsSalt()
	if string(afterSalt) != string(baselineSalt) {
		t.Fatal("StatsSalt changed after copy mutation")
	}
}
