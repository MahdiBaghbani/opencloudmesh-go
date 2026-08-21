// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package webdav

import (
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/webdav"
)

// Inputs holds dependencies for the WebDAV service constructor.
type Inputs struct {
	OutgoingShareRepo sharesoutgoing.OutgoingShareRepo
	TokenStore        token.TokenStore
	// ShareAccessObserver optionally runs after an authorized GET for a
	// resolved share, before the file is served; the validator uses it to
	// observe the capability exercise without the product handler knowing
	// about test runs.
	ShareAccessObserver webdav.ShareAccessObserver
}
