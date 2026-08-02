// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// Package interceptors provides cross-cutting HTTP middleware types and shared profile-config helpers.
package interceptors

import (
	"net/http"
)

// Middleware is an HTTP middleware function.
type Middleware func(http.Handler) http.Handler
