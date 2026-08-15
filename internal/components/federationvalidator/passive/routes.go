// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"net/http"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
)

const (
	// RouteStartCreateSession is POST /start for passive-core session creation.
	RouteStartCreateSession = "/start"

	// ValidatorServiceName is the HTTP service key for federation validator routes.
	ValidatorServiceName = "validator"
)

// CreateSessionRouteSpec returns the POST /start route spec for passive-core
// session creation. Ratelimit applies on every create-session request via the
// scan_public.start_public profile, not only on active-run branches.
func CreateSessionRouteSpec() service.RouteSpec {
	return service.RouteSpec{
		ID:            "validator-start-create-session",
		Service:       ValidatorServiceName,
		Method:        http.MethodPost,
		Pattern:       RouteStartCreateSession,
		SessionPolicy: service.SessionPublic,
		HandlerAuth:   service.HandlerAuthRateLimitOnly,
		Middleware:    []string{"ratelimit"},
		SurfaceClass:  service.SurfaceAPI,
		TrustClass:    service.TrustPeerNone,
	}
}
