// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package api

import (
	"net/http"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
)

const (
	// RouteHealthz is the API health check route path.
	RouteHealthz = "/healthz"
	// RouteAuthLogin is the API login route path.
	RouteAuthLogin = "/auth/login"
	// RouteAuthLogout is the API logout route path.
	RouteAuthLogout = "/auth/logout"
	// RouteAuthMe is the API current-user route path.
	RouteAuthMe = "/auth/me"
	// RouteInboxShares is the API inbox shares list route path.
	RouteInboxShares = "/inbox/shares"
	// RouteInboxShareDetail is the API inbox share detail route path.
	RouteInboxShareDetail = "/inbox/shares/{shareId}"
	// RouteInboxShareAccept is the API inbox share accept route path.
	RouteInboxShareAccept = "/inbox/shares/{shareId}/accept"
	// RouteInboxShareDecline is the API inbox share decline route path.
	RouteInboxShareDecline = "/inbox/shares/{shareId}/decline"
	// RouteInboxShareVerifyAccess is the API inbox share verify-access route path.
	RouteInboxShareVerifyAccess = "/inbox/shares/{shareId}/verify-access"
	// RouteInboxInvites is the API inbox invites list route path.
	RouteInboxInvites = "/inbox/invites"
	// RouteInboxInviteImport is the API inbox invite import route path.
	RouteInboxInviteImport = "/inbox/invites/import"
	// RouteInboxInviteAccept is the API inbox invite accept route path.
	RouteInboxInviteAccept = "/inbox/invites/{inviteId}/accept"
	// RouteInboxInviteDecline is the API inbox invite decline route path.
	RouteInboxInviteDecline = "/inbox/invites/{inviteId}/decline"
	// RouteSharesOutgoing is the API outgoing shares route path.
	RouteSharesOutgoing = "/shares/outgoing"
	// RouteInvitesOutgoing is the API outgoing invites route path.
	RouteInvitesOutgoing = "/invites/outgoing"
)

func init() {
	service.RegisterRouteSpecs(registeredRouteSpecs)
}

func registeredRouteSpecs(service.RouteOpts) []service.RouteSpec {
	return []service.RouteSpec{
		{
			ID:            service.RouteIDAPIHealthz,
			Service:       string(service.BuildAPI),
			Method:        http.MethodGet,
			Pattern:       RouteHealthz,
			SessionPolicy: service.SessionPublic,
			HandlerAuth:   service.HandlerAuthNone,
			SurfaceClass:  service.SurfaceAPI,
			TrustClass:    service.TrustPeerNone,
		},
		{
			ID:            "api-auth-login",
			Service:       string(service.BuildAPI),
			Method:        http.MethodPost,
			Pattern:       RouteAuthLogin,
			SessionPolicy: service.SessionPublic,
			HandlerAuth:   service.HandlerAuthRateLimitOnly,
			Middleware:    []string{"ratelimit"},
			SurfaceClass:  service.SurfaceAPI,
			TrustClass:    service.TrustPeerNone,
		},
		{
			ID:            "api-auth-logout",
			Service:       string(service.BuildAPI),
			Method:        http.MethodPost,
			Pattern:       RouteAuthLogout,
			SessionPolicy: service.SessionProtected,
			HandlerAuth:   service.HandlerAuthCurrentUser,
			SurfaceClass:  service.SurfaceAPI,
			TrustClass:    service.TrustPeerNone,
		},
		{
			ID:            "api-auth-me",
			Service:       string(service.BuildAPI),
			Method:        http.MethodGet,
			Pattern:       RouteAuthMe,
			SessionPolicy: service.SessionProtected,
			HandlerAuth:   service.HandlerAuthCurrentUser,
			SurfaceClass:  service.SurfaceAPI,
			TrustClass:    service.TrustPeerNone,
		},
		{
			ID:            "api-inbox-shares-list",
			Service:       string(service.BuildAPI),
			Method:        http.MethodGet,
			Pattern:       RouteInboxShares,
			SessionPolicy: service.SessionProtected,
			HandlerAuth:   service.HandlerAuthCurrentUser,
			SurfaceClass:  service.SurfaceAPI,
			TrustClass:    service.TrustPeerNone,
		},
		{
			ID:            "api-inbox-share-detail",
			Service:       string(service.BuildAPI),
			Method:        http.MethodGet,
			Pattern:       RouteInboxShareDetail,
			SessionPolicy: service.SessionProtected,
			HandlerAuth:   service.HandlerAuthCurrentUser,
			SurfaceClass:  service.SurfaceAPI,
			TrustClass:    service.TrustPeerNone,
		},
		{
			ID:            "api-inbox-share-accept",
			Service:       string(service.BuildAPI),
			Method:        http.MethodPost,
			Pattern:       RouteInboxShareAccept,
			SessionPolicy: service.SessionProtected,
			HandlerAuth:   service.HandlerAuthCurrentUser,
			SurfaceClass:  service.SurfaceAPI,
			TrustClass:    service.TrustPeerNone,
		},
		{
			ID:            "api-inbox-share-decline",
			Service:       string(service.BuildAPI),
			Method:        http.MethodPost,
			Pattern:       RouteInboxShareDecline,
			SessionPolicy: service.SessionProtected,
			HandlerAuth:   service.HandlerAuthCurrentUser,
			SurfaceClass:  service.SurfaceAPI,
			TrustClass:    service.TrustPeerNone,
		},
		{
			ID:                   "api-inbox-share-verify-access",
			Service:              string(service.BuildAPI),
			Method:               http.MethodPost,
			Pattern:              RouteInboxShareVerifyAccess,
			SessionPolicy:        service.SessionProtected,
			HandlerAuth:          service.HandlerAuthCurrentUser,
			SurfaceClass:         service.SurfaceAPI,
			OutboundProtocolKind: service.OutboundAccess,
			TrustClass:           service.TrustPeerNone,
		},
		{
			ID:            "api-inbox-invites-list",
			Service:       string(service.BuildAPI),
			Method:        http.MethodGet,
			Pattern:       RouteInboxInvites,
			SessionPolicy: service.SessionProtected,
			HandlerAuth:   service.HandlerAuthCurrentUser,
			SurfaceClass:  service.SurfaceAPI,
			TrustClass:    service.TrustPeerNone,
		},
		{
			ID:                   "api-inbox-invite-import",
			Service:              string(service.BuildAPI),
			Method:               http.MethodPost,
			Pattern:              RouteInboxInviteImport,
			SessionPolicy:        service.SessionProtected,
			HandlerAuth:          service.HandlerAuthCurrentUser,
			SurfaceClass:         service.SurfaceAPI,
			OutboundProtocolKind: service.OutboundInvites,
			TrustClass:           service.TrustPeerNone,
		},
		{
			ID:                   "api-inbox-invite-accept",
			Service:              string(service.BuildAPI),
			Method:               http.MethodPost,
			Pattern:              RouteInboxInviteAccept,
			SessionPolicy:        service.SessionProtected,
			HandlerAuth:          service.HandlerAuthCurrentUser,
			SurfaceClass:         service.SurfaceAPI,
			OutboundProtocolKind: service.OutboundInvites,
			TrustClass:           service.TrustPeerNone,
		},
		{
			ID:                   "api-inbox-invite-decline",
			Service:              string(service.BuildAPI),
			Method:               http.MethodPost,
			Pattern:              RouteInboxInviteDecline,
			SessionPolicy:        service.SessionProtected,
			HandlerAuth:          service.HandlerAuthCurrentUser,
			SurfaceClass:         service.SurfaceAPI,
			OutboundProtocolKind: service.OutboundInvites,
			TrustClass:           service.TrustPeerNone,
		},
		{
			ID:                   "api-shares-outgoing",
			Service:              string(service.BuildAPI),
			Method:               http.MethodPost,
			Pattern:              RouteSharesOutgoing,
			SessionPolicy:        service.SessionProtected,
			HandlerAuth:          service.HandlerAuthCurrentUser,
			SurfaceClass:         service.SurfaceAPI,
			OutboundProtocolKind: service.OutboundShares,
			TrustClass:           service.TrustPeerNone,
		},
		{
			ID:            "api-invites-outgoing",
			Service:       string(service.BuildAPI),
			Method:        http.MethodPost,
			Pattern:       RouteInvitesOutgoing,
			SessionPolicy: service.SessionProtected,
			HandlerAuth:   service.HandlerAuthCurrentUser,
			SurfaceClass:  service.SurfaceAPI,
			TrustClass:    service.TrustPeerNone,
		},
	}
}
