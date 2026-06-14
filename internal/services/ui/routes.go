package ui

import (
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
)

const (
	RouteLogin        = "/login"
	RouteInbox        = "/inbox"
	RouteOutgoing     = "/outgoing"
	RouteWAYF         = "/wayf"
	RouteAcceptInvite = "/accept-invite"
)

func init() {
	service.RegisterRouteSpecs(registeredRouteSpecs)
}

func registeredRouteSpecs(service.RouteOpts) []service.RouteSpec {
	return []service.RouteSpec{
		{
			ID:            "ui-login",
			Service:       "ui",
			Method:        "GET",
			Pattern:       RouteLogin,
			SessionPolicy: service.SessionPublic,
			HandlerAuth:   service.HandlerAuthNone,
			SurfaceClass:  service.SurfaceUI,
			TrustClass:    service.TrustPeerNone,
		},
		{
			ID:            "ui-inbox",
			Service:       "ui",
			Method:        "GET",
			Pattern:       RouteInbox,
			SessionPolicy: service.SessionProtected,
			HandlerAuth:   service.HandlerAuthNone,
			SurfaceClass:  service.SurfaceUI,
			TrustClass:    service.TrustPeerNone,
		},
		{
			ID:            "ui-outgoing",
			Service:       "ui",
			Method:        "GET",
			Pattern:       RouteOutgoing,
			SessionPolicy: service.SessionProtected,
			HandlerAuth:   service.HandlerAuthNone,
			SurfaceClass:  service.SurfaceUI,
			TrustClass:    service.TrustPeerNone,
		},
		{
			ID:               "ui-wayf",
			Service:          "ui",
			Method:           "GET",
			Pattern:          RouteWAYF,
			SessionPolicy:    service.SessionPublicWhenWAYF,
			HandlerAuth:      service.HandlerAuthNone,
			SurfaceClass:     service.SurfaceUI,
			DiscoveryFields:  []string{"invite-wayf"},
			FeatureCondition: service.FeatureWAYFEnabled,
			TrustClass:       service.TrustPeerNone,
		},
		{
			ID:               "ui-accept-invite",
			Service:          "ui",
			Method:           "GET",
			Pattern:          RouteAcceptInvite,
			SessionPolicy:    service.SessionProtected,
			HandlerAuth:      service.HandlerAuthNone,
			SurfaceClass:     service.SurfaceUI,
			DiscoveryFields:  []string{"inviteAcceptDialog"},
			FeatureCondition: service.FeatureInviteAcceptEnabled,
			TrustClass:       service.TrustPeerNone,
		},
	}
}
