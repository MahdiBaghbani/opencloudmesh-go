// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package crypto_test

import (
	"bytes"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/crypto"
)

func TestPadCoord(t *testing.T) {
	t.Parallel()

	b := []byte{0x01, 0x02, 0x03}

	got := crypto.PadCoord(b, 3)
	if !bytes.Equal(got, b) {
		t.Fatalf("PadCoord(%v, 3) = %v, want unchanged %v", b, got, b)
	}

	got = crypto.PadCoord(b, 2)
	if !bytes.Equal(got, b) {
		t.Fatalf("PadCoord(%v, 2) = %v, want unchanged %v", b, got, b)
	}

	want := []byte{0x00, 0x00, 0x01, 0x02, 0x03}

	got = crypto.PadCoord(b, 5)
	if !bytes.Equal(got, want) {
		t.Fatalf("PadCoord(%v, 5) = %v, want %v", b, got, want)
	}
}
