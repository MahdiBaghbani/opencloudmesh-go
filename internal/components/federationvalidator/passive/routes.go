// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/catalog"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
)

const (
	// RouteStartCreateSession is POST /start for passive-core session creation.
	RouteStartCreateSession = catalog.PatternStart

	// RouteHTMLStart is GET /start for the validator start page.
	RouteHTMLStart = catalog.PatternStart

	// RouteStopSession is POST /stop for core-only terminalization.
	RouteStopSession = catalog.PatternStop

	// RouteAPIScan is GET /api/scan on the validator service router.
	RouteAPIScan = catalog.PatternScan

	// RouteAPIManifest is GET /api/manifest on the validator service router.
	RouteAPIManifest = catalog.PatternManifest

	// RouteAPIStatistics is GET /api/statistics on the validator service router.
	RouteAPIStatistics = catalog.PatternStatistics

	// RouteAPISession is GET /api/session/{id} on the validator service router.
	RouteAPISession = catalog.PatternSession

	// RouteAPISessionInvite is POST /api/session/{id}/invite.
	RouteAPISessionInvite = catalog.PatternClaim

	// RouteAPISessionAbort is POST /api/session/{id}/abort.
	RouteAPISessionAbort = catalog.PatternAbort

	// RouteAPIReport is GET /api/report/{id} on the validator service router.
	RouteAPIReport = catalog.PatternReportJSON

	// RouteAPIReportRetention is PATCH /api/report/{id}/retention.
	RouteAPIReportRetention = catalog.PatternReportRetain

	// RouteAPIReportLock is POST /api/report/{id}/lock.
	RouteAPIReportLock = catalog.PatternReportLock

	// RouteHTMLReport is GET /report/{id} beside the plane-A API routes.
	RouteHTMLReport = catalog.PatternHTMLReport

	// ValidatorServiceName is the HTTP service key for federation validator routes.
	ValidatorServiceName = catalog.ServicePrefix
)

// StartPageRouteSpec returns the GET /start route spec for the start HTML page.
func StartPageRouteSpec() service.RouteSpec {
	return catalogSpec(service.RouteIDValidatorHTMLStart)
}

// CreateSessionRouteSpec returns the POST /start route spec for passive-core
// session creation.
func CreateSessionRouteSpec() service.RouteSpec {
	return catalogSpec(service.RouteIDValidatorStartCreateSession)
}

// ClaimInviteRouteSpec returns POST /api/session/{id}/invite for the
// one-time session invite claim.
func ClaimInviteRouteSpec() service.RouteSpec {
	return catalogSpec(service.RouteIDValidatorAPISessionInvite)
}

// StopSessionRouteSpec returns POST /stop for passive_complete terminalization.
func StopSessionRouteSpec() service.RouteSpec {
	return catalogSpec(service.RouteIDValidatorStopSession)
}

// AbortSessionRouteSpec returns POST /api/session/{id}/abort.
func AbortSessionRouteSpec() service.RouteSpec {
	return catalogSpec(service.RouteIDValidatorAPISessionAbort)
}

func catalogSpec(id string) service.RouteSpec {
	def, ok := catalog.Lookup(id)
	if !ok {
		return service.RouteSpec{}
	}

	return def.ToRouteSpec()
}
