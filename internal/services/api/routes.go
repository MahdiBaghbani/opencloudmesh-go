package api

import (
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
)

const (
	RouteHealthz                = "/healthz"
	RouteAuthLogin              = "/auth/login"
	RouteAuthLogout             = "/auth/logout"
	RouteAuthMe                 = "/auth/me"
	RouteInboxShares            = "/inbox/shares"
	RouteInboxShareDetail       = "/inbox/shares/{shareId}"
	RouteInboxShareAccept       = "/inbox/shares/{shareId}/accept"
	RouteInboxShareDecline      = "/inbox/shares/{shareId}/decline"
	RouteInboxShareVerifyAccess = "/inbox/shares/{shareId}/verify-access"
	RouteInboxInvites           = "/inbox/invites"
	RouteInboxInviteImport      = "/inbox/invites/import"
	RouteInboxInviteAccept      = "/inbox/invites/{inviteId}/accept"
	RouteInboxInviteDecline     = "/inbox/invites/{inviteId}/decline"
	RouteSharesOutgoing         = "/shares/outgoing"
	RouteInvitesOutgoing        = "/invites/outgoing"
)

func init() {
	service.RegisterRouteSpecs(registeredRouteSpecs)
}

func registeredRouteSpecs(service.RouteOpts) []service.RouteSpec {
	return []service.RouteSpec{
		{
			ID:            service.RouteIDAPIHealthz,
			Service:       "api",
			Method:        "GET",
			Pattern:       RouteHealthz,
			SessionPolicy: service.SessionPublic,
			HandlerAuth:   service.HandlerAuthNone,
			SurfaceClass:  service.SurfaceAPI,
			TrustClass:    service.TrustPeerNone,
		},
		{
			ID:            "api-auth-login",
			Service:       "api",
			Method:        "POST",
			Pattern:       RouteAuthLogin,
			SessionPolicy: service.SessionPublic,
			HandlerAuth:   service.HandlerAuthRateLimitOnly,
			Middleware:    []string{"ratelimit"},
			SurfaceClass:  service.SurfaceAPI,
			TrustClass:    service.TrustPeerNone,
		},
		{
			ID:            "api-auth-logout",
			Service:       "api",
			Method:        "POST",
			Pattern:       RouteAuthLogout,
			SessionPolicy: service.SessionProtected,
			HandlerAuth:   service.HandlerAuthCurrentUser,
			SurfaceClass:  service.SurfaceAPI,
			TrustClass:    service.TrustPeerNone,
		},
		{
			ID:            "api-auth-me",
			Service:       "api",
			Method:        "GET",
			Pattern:       RouteAuthMe,
			SessionPolicy: service.SessionProtected,
			HandlerAuth:   service.HandlerAuthCurrentUser,
			SurfaceClass:  service.SurfaceAPI,
			TrustClass:    service.TrustPeerNone,
		},
		{
			ID:            "api-inbox-shares-list",
			Service:       "api",
			Method:        "GET",
			Pattern:       RouteInboxShares,
			SessionPolicy: service.SessionProtected,
			HandlerAuth:   service.HandlerAuthCurrentUser,
			SurfaceClass:  service.SurfaceAPI,
			TrustClass:    service.TrustPeerNone,
		},
		{
			ID:            "api-inbox-share-detail",
			Service:       "api",
			Method:        "GET",
			Pattern:       RouteInboxShareDetail,
			SessionPolicy: service.SessionProtected,
			HandlerAuth:   service.HandlerAuthCurrentUser,
			SurfaceClass:  service.SurfaceAPI,
			TrustClass:    service.TrustPeerNone,
		},
		{
			ID:            "api-inbox-share-accept",
			Service:       "api",
			Method:        "POST",
			Pattern:       RouteInboxShareAccept,
			SessionPolicy: service.SessionProtected,
			HandlerAuth:   service.HandlerAuthCurrentUser,
			SurfaceClass:  service.SurfaceAPI,
			TrustClass:    service.TrustPeerNone,
		},
		{
			ID:            "api-inbox-share-decline",
			Service:       "api",
			Method:        "POST",
			Pattern:       RouteInboxShareDecline,
			SessionPolicy: service.SessionProtected,
			HandlerAuth:   service.HandlerAuthCurrentUser,
			SurfaceClass:  service.SurfaceAPI,
			TrustClass:    service.TrustPeerNone,
		},
		{
			ID:                   "api-inbox-share-verify-access",
			Service:              "api",
			Method:               "POST",
			Pattern:              RouteInboxShareVerifyAccess,
			SessionPolicy:        service.SessionProtected,
			HandlerAuth:          service.HandlerAuthCurrentUser,
			SurfaceClass:         service.SurfaceAPI,
			OutboundProtocolKind: service.OutboundAccess,
			TrustClass:           service.TrustPeerNone,
		},
		{
			ID:            "api-inbox-invites-list",
			Service:       "api",
			Method:        "GET",
			Pattern:       RouteInboxInvites,
			SessionPolicy: service.SessionProtected,
			HandlerAuth:   service.HandlerAuthCurrentUser,
			SurfaceClass:  service.SurfaceAPI,
			TrustClass:    service.TrustPeerNone,
		},
		{
			ID:                   "api-inbox-invite-import",
			Service:              "api",
			Method:               "POST",
			Pattern:              RouteInboxInviteImport,
			SessionPolicy:        service.SessionProtected,
			HandlerAuth:          service.HandlerAuthCurrentUser,
			SurfaceClass:         service.SurfaceAPI,
			OutboundProtocolKind: service.OutboundInvites,
			TrustClass:           service.TrustPeerNone,
		},
		{
			ID:                   "api-inbox-invite-accept",
			Service:              "api",
			Method:               "POST",
			Pattern:              RouteInboxInviteAccept,
			SessionPolicy:        service.SessionProtected,
			HandlerAuth:          service.HandlerAuthCurrentUser,
			SurfaceClass:         service.SurfaceAPI,
			OutboundProtocolKind: service.OutboundInvites,
			TrustClass:           service.TrustPeerNone,
		},
		{
			ID:                   "api-inbox-invite-decline",
			Service:              "api",
			Method:               "POST",
			Pattern:              RouteInboxInviteDecline,
			SessionPolicy:        service.SessionProtected,
			HandlerAuth:          service.HandlerAuthCurrentUser,
			SurfaceClass:         service.SurfaceAPI,
			OutboundProtocolKind: service.OutboundInvites,
			TrustClass:           service.TrustPeerNone,
		},
		{
			ID:                   "api-shares-outgoing",
			Service:              "api",
			Method:               "POST",
			Pattern:              RouteSharesOutgoing,
			SessionPolicy:        service.SessionProtected,
			HandlerAuth:          service.HandlerAuthCurrentUser,
			SurfaceClass:         service.SurfaceAPI,
			OutboundProtocolKind: service.OutboundShares,
			TrustClass:           service.TrustPeerNone,
		},
		{
			ID:            "api-invites-outgoing",
			Service:       "api",
			Method:        "POST",
			Pattern:       RouteInvitesOutgoing,
			SessionPolicy: service.SessionProtected,
			HandlerAuth:   service.HandlerAuthCurrentUser,
			SurfaceClass:  service.SurfaceAPI,
			TrustClass:    service.TrustPeerNone,
		},
	}
}
