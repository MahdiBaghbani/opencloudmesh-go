// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package ocmaux

import (
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
)

const (
	// RouteFederations is the OCM auxiliary federations route path.
	RouteFederations = "/federations"
	// RouteDiscover is the OCM auxiliary discover route path.
	RouteDiscover = "/discover"
)

func init() {
	service.RegisterRouteSpecs(registeredRouteSpecs)
}

func registeredRouteSpecs(service.RouteOpts) []service.RouteSpec {
	return []service.RouteSpec{
		{
			ID:            "ocmaux-federations",
			Service:       "ocmaux",
			Method:        "GET",
			Pattern:       RouteFederations,
			SessionPolicy: service.SessionPublic,
			HandlerAuth:   service.HandlerAuthNone,
			SurfaceClass:  service.SurfaceHelper,
			TrustClass:    service.TrustPeerNone,
		},
		{
			ID:            "ocmaux-discover",
			Service:       "ocmaux",
			Method:        "GET",
			Pattern:       RouteDiscover,
			SessionPolicy: service.SessionPublic,
			HandlerAuth:   service.HandlerAuthRateLimitOnly,
			Middleware:    []string{"ratelimit"},
			SurfaceClass:  service.SurfaceHelper,
			TrustClass:    service.TrustPeerNone,
		},
	}
}
