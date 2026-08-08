// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package sigalg

// JOSE algorithm aliases accepted by Normalize before mapping to RFC 9421 names.
const (
	joseEdDSA = "EDDSA"
	joseES256 = "ES256"
	joseES384 = "ES384"
	joseRS256 = "RS256"
	joseRS384 = "RS384"
	joseRS512 = "RS512"
)
