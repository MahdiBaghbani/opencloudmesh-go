// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package server

import (
	"net/http"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/realip"
)

// ServerDeps holds dependencies injected into the HTTP server at construction.
type ServerDeps struct {
	RealIP   *realip.TrustedProxies
	AuthGate func(requireAuth func(string) bool) func(http.Handler) http.Handler
}
