// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package wellknown

import (
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
)

const (
	// RouteWellKnownOCM is the well-known OCM route path.
	RouteWellKnownOCM = "/.well-known/ocm"
	// RouteWellKnownOCMSlash is the well-known OCM route path with trailing slash.
	RouteWellKnownOCMSlash = "/.well-known/ocm/"
)

func init() {
	service.RegisterRouteSpecs(registeredRouteSpecs)
}

func registeredRouteSpecs(service.RouteOpts) []service.RouteSpec {
	return []service.RouteSpec{
		{
			ID:              "wellknown-ocm",
			Service:         "wellknown",
			Method:          "GET",
			Pattern:         RouteWellKnownOCM,
			SessionPolicy:   service.SessionPublic,
			HandlerAuth:     service.HandlerAuthNone,
			SurfaceClass:    service.SurfaceDiscovery,
			DiscoveryFields: []string{"end-point", "provider"},
			TrustClass:      service.TrustPeerNone,
		},
		{
			ID:              "wellknown-ocm-slash",
			Service:         "wellknown",
			Method:          "GET",
			Pattern:         RouteWellKnownOCMSlash,
			SessionPolicy:   service.SessionPublic,
			HandlerAuth:     service.HandlerAuthNone,
			SurfaceClass:    service.SurfaceDiscovery,
			DiscoveryFields: []string{"end-point", "provider"},
			TrustClass:      service.TrustPeerNone,
		},
	}
}
