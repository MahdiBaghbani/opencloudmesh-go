// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package ocmaux

import (
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peertrust"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/interceptors/ratelimit"
)

// Inputs holds dependencies for the ocmaux service constructor.
type Inputs struct {
	TrustGroupMgr       *peertrust.TrustGroupManager
	DiscoveryClient     *discovery.Client
	Ratelimit           ratelimit.Inputs
	InterceptorProfiles map[string]map[string]any
}
