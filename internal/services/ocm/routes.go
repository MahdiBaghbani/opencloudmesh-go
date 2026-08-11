// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package ocm

import (
	"net/http"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
)

const (
	// RouteShares is the OCM shares route path.
	RouteShares = "/shares"
	// RouteInviteAccepted is the OCM invite-accepted route path.
	RouteInviteAccepted = "/invite-accepted"
	// RouteNotifications is the OCM notifications route path.
	RouteNotifications = "/notifications"
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
			Service:        string(service.BuildOCM),
			Method:         http.MethodPost,
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
			Service:        string(service.BuildOCM),
			Method:         http.MethodPost,
			Pattern:        RouteInviteAccepted,
			SessionPolicy:  service.SessionPublic,
			HandlerAuth:    service.HandlerAuthRequiredHTTPSig,
			SurfaceClass:   service.SurfaceProtocol,
			TrustClass:     service.TrustPeerRequired,
			BodyLimitBytes: service.OCMProtocolBodyLimitBytes,
			PeerResolution: service.PeerResolutionInviteAccepted,
		},
		{
			ID:             "ocm-notifications",
			Service:        string(service.BuildOCM),
			Method:         http.MethodPost,
			Pattern:        RouteNotifications,
			SessionPolicy:  service.SessionPublic,
			HandlerAuth:    service.HandlerAuthRequiredHTTPSig,
			SurfaceClass:   service.SurfaceProtocol,
			TrustClass:     service.TrustPeerRequired,
			BodyLimitBytes: service.OCMProtocolBodyLimitBytes,
			PeerResolution: service.PeerResolutionNotifications,
		},
		{
			ID:              service.RouteIDOCMToken,
			Service:         string(service.BuildOCM),
			Method:          http.MethodPost,
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
			Service:         string(service.BuildOCM),
			Method:          http.MethodGet,
			Pattern:         RouteJWKS,
			SessionPolicy:   service.SessionPublic,
			HandlerAuth:     service.HandlerAuthNone,
			SurfaceClass:    service.SurfaceDiscovery,
			TrustClass:      service.TrustPeerNone,
			DiscoveryFields: []string{"jwks"},
		},
	}
}
