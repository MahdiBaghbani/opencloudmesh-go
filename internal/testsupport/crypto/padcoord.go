// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// Package crypto provides shared test helpers for platform crypto tests.
// Helpers consolidate duplicated setup used across jwks, sigalg, httpsig, and keys tests.
package crypto

// PadCoord zero-pads b on the left to size bytes when len(b) < size.
func PadCoord(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}

	out := make([]byte, size)
	copy(out[size-len(b):], b)

	return out
}
