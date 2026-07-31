// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package webdav

import (
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
)

const (
	// RouteOCMWildcard is the WebDAV route pattern for OCM wildcard mounts.
	RouteOCMWildcard = "/ocm/*"
)

func init() {
	service.RegisterRouteSpecs(registeredRouteSpecs)
}

func registeredRouteSpecs(service.RouteOpts) []service.RouteSpec {
	return []service.RouteSpec{
		{
			ID:            service.RouteIDWebDAVOCMWildcard,
			Service:       "webdav",
			Method:        "*",
			Pattern:       RouteOCMWildcard,
			SessionPolicy: service.SessionPublic,
			HandlerAuth:   service.HandlerAuthBearer,
			SurfaceClass:  service.SurfaceWebDAV,
			TrustClass:    service.TrustPeerNone,
		},
	}
}
