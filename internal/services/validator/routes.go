// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validator

import (
	"net/http"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
)

const (
	// RouteStartCreateSession is POST /validator/start for passive-core create
	// and active extension.
	RouteStartCreateSession = "/start"
	// RouteStopSession is POST /validator/stop for core-only terminalization.
	RouteStopSession = "/stop"
	// RouteAPIScan is GET /validator/api/scan.
	RouteAPIScan = "/api/scan"
	// RouteAPISession is GET /validator/api/session/{id}.
	RouteAPISession = "/api/session/{id}"
	// RouteAPIReport is GET /validator/api/report/{id}.
	// Duplicated in the passive package because that package cannot import
	// services/validator; keep the strings synchronized.
	RouteAPIReport = "/api/report/{id}"
	// RouteAPIReportRetention is PATCH /validator/api/report/{id}/retention.
	// Duplicated in the passive package; keep the strings synchronized.
	RouteAPIReportRetention = "/api/report/{id}/retention"
	// RouteAPIReportLock is POST /validator/api/report/{id}/lock.
	// Duplicated in the passive package; keep the strings synchronized.
	RouteAPIReportLock = "/api/report/{id}/lock"
	// RouteHTMLReport is GET /validator/report/{id}.
	// Duplicated in the passive package; keep the strings synchronized.
	RouteHTMLReport = "/report/{id}"
	// RouteAPIManifest is GET /validator/api/manifest.
	RouteAPIManifest = "/api/manifest"
	// RouteAPIStatistics is GET /validator/api/statistics.
	RouteAPIStatistics = "/api/statistics"
)

func init() {
	service.RegisterRouteSpecs(registeredRouteSpecs)
}

func registeredRouteSpecs(_ service.RouteOpts) []service.RouteSpec {
	return []service.RouteSpec{
		{
			ID:               "validator-start-create-session",
			Service:          string(service.BuildValidator),
			Method:           http.MethodPost,
			Pattern:          RouteStartCreateSession,
			SessionPolicy:    service.SessionPublic,
			HandlerAuth:      service.HandlerAuthRateLimitOnly,
			Middleware:       []string{"ratelimit"},
			SurfaceClass:     service.SurfaceAPI,
			TrustClass:       service.TrustPeerNone,
			FeatureCondition: service.FeatureValidatorEnabled,
		},
		{
			ID:               "validator-stop-session",
			Service:          string(service.BuildValidator),
			Method:           http.MethodPost,
			Pattern:          RouteStopSession,
			SessionPolicy:    service.SessionPublic,
			HandlerAuth:      service.HandlerAuthNone,
			SurfaceClass:     service.SurfaceAPI,
			TrustClass:       service.TrustPeerNone,
			FeatureCondition: service.FeatureValidatorEnabled,
		},
		{
			ID:               "validator-api-scan",
			Service:          string(service.BuildValidator),
			Method:           http.MethodGet,
			Pattern:          RouteAPIScan,
			SessionPolicy:    service.SessionPublic,
			HandlerAuth:      service.HandlerAuthNone,
			SurfaceClass:     service.SurfaceAPI,
			TrustClass:       service.TrustPeerNone,
			FeatureCondition: service.FeatureValidatorEnabled,
		},
		{
			ID:               service.RouteIDValidatorAPISession,
			Service:          string(service.BuildValidator),
			Method:           http.MethodGet,
			Pattern:          RouteAPISession,
			SessionPolicy:    service.SessionPublic,
			HandlerAuth:      service.HandlerAuthNone,
			SurfaceClass:     service.SurfaceAPI,
			TrustClass:       service.TrustPeerNone,
			FeatureCondition: service.FeatureValidatorEnabled,
		},
		{
			ID:               service.RouteIDValidatorAPIReport,
			Service:          string(service.BuildValidator),
			Method:           http.MethodGet,
			Pattern:          RouteAPIReport,
			SessionPolicy:    service.SessionPublic,
			HandlerAuth:      service.HandlerAuthNone,
			SurfaceClass:     service.SurfaceAPI,
			TrustClass:       service.TrustPeerNone,
			FeatureCondition: service.FeatureValidatorEnabled,
		},
		{
			ID:               service.RouteIDValidatorAPIReportRetention,
			Service:          string(service.BuildValidator),
			Method:           http.MethodPatch,
			Pattern:          RouteAPIReportRetention,
			SessionPolicy:    service.SessionPublic,
			HandlerAuth:      service.HandlerAuthNone,
			SurfaceClass:     service.SurfaceAPI,
			TrustClass:       service.TrustPeerNone,
			FeatureCondition: service.FeatureValidatorEnabled,
		},
		{
			ID:               service.RouteIDValidatorAPIReportLock,
			Service:          string(service.BuildValidator),
			Method:           http.MethodPost,
			Pattern:          RouteAPIReportLock,
			SessionPolicy:    service.SessionPublic,
			HandlerAuth:      service.HandlerAuthNone,
			SurfaceClass:     service.SurfaceAPI,
			TrustClass:       service.TrustPeerNone,
			FeatureCondition: service.FeatureValidatorEnabled,
		},
		{
			ID:               service.RouteIDValidatorHTMLReport,
			Service:          string(service.BuildValidator),
			Method:           http.MethodGet,
			Pattern:          RouteHTMLReport,
			SessionPolicy:    service.SessionPublic,
			HandlerAuth:      service.HandlerAuthNone,
			SurfaceClass:     service.SurfaceUI,
			TrustClass:       service.TrustPeerNone,
			FeatureCondition: service.FeatureValidatorEnabled,
		},
		{
			ID:               "validator-api-manifest",
			Service:          string(service.BuildValidator),
			Method:           http.MethodGet,
			Pattern:          RouteAPIManifest,
			SessionPolicy:    service.SessionPublic,
			HandlerAuth:      service.HandlerAuthNone,
			SurfaceClass:     service.SurfaceAPI,
			TrustClass:       service.TrustPeerNone,
			FeatureCondition: service.FeatureValidatorEnabled,
		},
		{
			ID:               service.RouteIDValidatorAPIStatistics,
			Service:          string(service.BuildValidator),
			Method:           http.MethodGet,
			Pattern:          RouteAPIStatistics,
			SessionPolicy:    service.SessionPublic,
			HandlerAuth:      service.HandlerAuthNone,
			SurfaceClass:     service.SurfaceAPI,
			TrustClass:       service.TrustPeerNone,
			FeatureCondition: service.FeatureValidatorEnabled,
		},
	}
}
