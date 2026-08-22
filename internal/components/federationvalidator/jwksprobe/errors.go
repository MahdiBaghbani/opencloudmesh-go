// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package jwksprobe

import "errors"

var (
	errEmptyURI  = errors.New("jwksprobe: empty jwks uri")
	errNilClient = errors.New("jwksprobe: nil http client")
	errEmptySet  = errors.New("jwksprobe: empty key set")
	errTooLarge  = errors.New("jwksprobe: response too large")
)
