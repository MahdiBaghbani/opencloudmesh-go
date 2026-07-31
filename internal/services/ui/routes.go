// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package ui

import (
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
)

const (
	// RouteLogin is the UI login route path.
	RouteLogin = "/login"
	// RouteInbox is the UI inbox route path.
	RouteInbox = "/inbox"
	// RouteOutgoing is the UI outgoing route path.
	RouteOutgoing = "/outgoing"
	// RouteWAYF is the UI WAYF route path.
	RouteWAYF = "/wayf"
	// RouteAcceptInvite is the UI accept-invite route path.
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
			ID:               service.RouteIDUIWAYF,
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
			ID:               service.RouteIDUIAcceptInvite,
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
