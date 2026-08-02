// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package ratelimit

import (
	"net/http"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache"
)

// Inputs holds dependencies for the ratelimit interceptor constructor.
type Inputs struct {
	Cache   cache.Counter
	KeyFunc func(*http.Request) string
}
