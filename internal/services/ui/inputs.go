// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package ui

import (
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/localidentity"
)

// Inputs holds dependencies for the UI service constructor.
type Inputs struct {
	LocalIdentity localidentity.Identity
}
