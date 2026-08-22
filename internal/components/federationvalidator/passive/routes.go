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

	// RouteStopSession is POST /stop for core-only terminalization.
	RouteStopSession = "/stop"

	// RouteAPIScan is GET /api/scan on the validator service router.
	RouteAPIScan = "/api/scan"

	// RouteAPIManifest is GET /api/manifest on the validator service router.
	RouteAPIManifest = "/api/manifest"

	// RouteAPIStatistics is GET /api/statistics on the validator service router.
	RouteAPIStatistics = "/api/statistics"

	// RouteAPISession is GET /api/session/{id} on the validator service router.
	RouteAPISession = "/api/session/{id}"

	// RouteAPISessionInvite is POST /api/session/{id}/invite.
	// Duplicated in services/validator; keep the strings synchronized.
	RouteAPISessionInvite = "/api/session/{id}/invite"

	// RouteAPISessionAbort is POST /api/session/{id}/abort.
	// Duplicated in services/validator; keep the strings synchronized.
	RouteAPISessionAbort = "/api/session/{id}/abort"

	// RouteAPIReport is GET /api/report/{id} on the validator service router.
	// Duplicated in services/validator because this package cannot import that
	// service package; keep the strings synchronized.
	RouteAPIReport = "/api/report/{id}"

	// RouteAPIReportRetention is PATCH /api/report/{id}/retention.
	// Duplicated in services/validator; keep the strings synchronized.
	RouteAPIReportRetention = "/api/report/{id}/retention"

	// RouteAPIReportLock is POST /api/report/{id}/lock.
	// Duplicated in services/validator; keep the strings synchronized.
	RouteAPIReportLock = "/api/report/{id}/lock"

	// RouteHTMLReport is GET /report/{id} beside the plane-A API routes.
	// Duplicated in services/validator; keep the strings synchronized.
	RouteHTMLReport = "/report/{id}"

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

// ClaimInviteRouteSpec returns POST /api/session/{id}/invite for the
// one-time session invite claim. Ratelimit uses the same start_public
// profile as create-session.
func ClaimInviteRouteSpec() service.RouteSpec {
	return service.RouteSpec{
		ID:            service.RouteIDValidatorAPISessionInvite,
		Service:       ValidatorServiceName,
		Method:        http.MethodPost,
		Pattern:       RouteAPISessionInvite,
		SessionPolicy: service.SessionPublic,
		HandlerAuth:   service.HandlerAuthRateLimitOnly,
		Middleware:    []string{"ratelimit"},
		SurfaceClass:  service.SurfaceAPI,
		TrustClass:    service.TrustPeerNone,
	}
}

// StopSessionRouteSpec returns POST /stop for passive_complete terminalization.
func StopSessionRouteSpec() service.RouteSpec {
	return service.RouteSpec{
		ID:            "validator-stop-session",
		Service:       ValidatorServiceName,
		Method:        http.MethodPost,
		Pattern:       RouteStopSession,
		SessionPolicy: service.SessionPublic,
		HandlerAuth:   service.HandlerAuthNone,
		SurfaceClass:  service.SurfaceAPI,
		TrustClass:    service.TrustPeerNone,
	}
}

// AbortSessionRouteSpec returns POST /api/session/{id}/abort for an
// operator-initiated hard-fail of an active run.
func AbortSessionRouteSpec() service.RouteSpec {
	return service.RouteSpec{
		ID:            service.RouteIDValidatorAPISessionAbort,
		Service:       ValidatorServiceName,
		Method:        http.MethodPost,
		Pattern:       RouteAPISessionAbort,
		SessionPolicy: service.SessionPublic,
		HandlerAuth:   service.HandlerAuthNone,
		SurfaceClass:  service.SurfaceAPI,
		TrustClass:    service.TrustPeerNone,
	}
}
