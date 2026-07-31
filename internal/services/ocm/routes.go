// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package ocm

import (
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
)

const (
	// RouteShares is the OCM shares route path.
	RouteShares = "/shares"
	// RouteInviteAccepted is the OCM invite-accepted route path.
	RouteInviteAccepted = "/invite-accepted"
	// RouteJWKS is the OCM local JWKS route path.
	RouteJWKS = "/jwks"
)

func init() {
	service.RegisterRouteSpecs(registeredRouteSpecs)
}

func tokenRoutePattern(opts service.RouteOpts) string {
	path := opts.TokenExchangePath
	if path == "" {
		path = "token"
	}

	return "/" + path
}

func registeredRouteSpecs(opts service.RouteOpts) []service.RouteSpec {
	tokenPattern := tokenRoutePattern(opts)

	return []service.RouteSpec{
		{
			ID:             "ocm-shares",
			Service:        "ocm",
			Method:         "POST",
			Pattern:        RouteShares,
			SessionPolicy:  service.SessionPublic,
			HandlerAuth:    service.HandlerAuthRequiredHTTPSig,
			SurfaceClass:   service.SurfaceProtocol,
			TrustClass:     service.TrustPeerRequired,
			BodyLimitBytes: service.OCMProtocolBodyLimitBytes,
			PeerResolution: service.PeerResolutionShares,
		},
		{
			ID:             "ocm-invite-accepted",
			Service:        "ocm",
			Method:         "POST",
			Pattern:        RouteInviteAccepted,
			SessionPolicy:  service.SessionPublic,
			HandlerAuth:    service.HandlerAuthRequiredHTTPSig,
			SurfaceClass:   service.SurfaceProtocol,
			TrustClass:     service.TrustPeerRequired,
			BodyLimitBytes: service.OCMProtocolBodyLimitBytes,
			PeerResolution: service.PeerResolutionInviteAccepted,
		},
		{
			ID:              service.RouteIDOCMToken,
			Service:         "ocm",
			Method:          "POST",
			Pattern:         tokenPattern,
			SessionPolicy:   service.SessionPublic,
			HandlerAuth:     service.HandlerAuthRequiredHTTPSig,
			SurfaceClass:    service.SurfaceProtocol,
			TrustClass:      service.TrustPeerRequired,
			DiscoveryFields: []string{"tokenEndPoint"},
			BodyLimitBytes:  service.OCMProtocolBodyLimitBytes,
			PeerResolution:  service.PeerResolutionToken,
		},
		{
			ID:              "ocm-jwks",
			Service:         "ocm",
			Method:          "GET",
			Pattern:         RouteJWKS,
			SessionPolicy:   service.SessionPublic,
			HandlerAuth:     service.HandlerAuthNone,
			SurfaceClass:    service.SurfaceDiscovery,
			TrustClass:      service.TrustPeerNone,
			DiscoveryFields: []string{"jwks"},
		},
	}
}
