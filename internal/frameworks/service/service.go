// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package service

import (
	"net/http"
)

// Service represents an HTTP service constructed via the static wiring table and mounted on the host router.
type Service interface {
	Handler() http.Handler
	Prefix() string
	Close() error
}
