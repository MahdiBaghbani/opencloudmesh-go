// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validator

import (
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/catalog"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
)

const (
	// RouteStartCreateSession is POST /validator/start for passive-core create
	// and active extension.
	RouteStartCreateSession = catalog.PatternStart
	// RouteHTMLStart is GET /validator/start for the start page.
	RouteHTMLStart = catalog.PatternStart
	// RouteStopSession is POST /validator/stop for core-only terminalization.
	RouteStopSession = catalog.PatternStop
	// RouteAPIScan is GET /validator/api/scan.
	RouteAPIScan = catalog.PatternScan
	// RouteAPISession is GET /validator/api/session/{id}.
	RouteAPISession = catalog.PatternSession
	// RouteAPISessionInvite is POST /validator/api/session/{id}/invite.
	RouteAPISessionInvite = catalog.PatternClaim
	// RouteAPISessionAbort is POST /validator/api/session/{id}/abort.
	RouteAPISessionAbort = catalog.PatternAbort
	// RouteAPISessionReverseInvite is POST /validator/api/session/{id}/reverse-invite.
	RouteAPISessionReverseInvite = catalog.PatternPaste
	// RouteAPIReport is GET /validator/api/report/{id}.
	RouteAPIReport = catalog.PatternReportJSON
	// RouteAPIReportRetention is PATCH /validator/api/report/{id}/retention.
	RouteAPIReportRetention = catalog.PatternReportRetain
	// RouteAPIReportLock is POST /validator/api/report/{id}/lock.
	RouteAPIReportLock = catalog.PatternReportLock
	// RouteHTMLReport is GET /validator/report/{id}.
	RouteHTMLReport = catalog.PatternHTMLReport
	// RouteAPIManifest is GET /validator/api/manifest.
	RouteAPIManifest = catalog.PatternManifest
	// RouteAPIStatistics is GET /validator/api/statistics.
	RouteAPIStatistics = catalog.PatternStatistics
)

func init() {
	service.RegisterRouteSpecs(registeredRouteSpecs)
}

func registeredRouteSpecs(_ service.RouteOpts) []service.RouteSpec {
	return catalog.RouteSpecs()
}
