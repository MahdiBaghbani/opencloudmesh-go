// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
)

// PlaneAAPIRoutePatterns holds service-relative GET /api/* patterns for plane-A.
type PlaneAAPIRoutePatterns struct {
	Scan       string
	Session    string
	Manifest   string
	Statistics string
	Report     string
}

// MountPlaneARoutes registers plane-A validator routes on r. startRatelimit may
// be nil to skip the shared wrapper on POST /start and the invite claim.
func MountPlaneARoutes(
	r chi.Router,
	h *Handler,
	startRatelimit func(http.Handler) http.Handler,
	api PlaneAAPIRoutePatterns,
) {
	MountPlaneARoutesWithHeal(r, h, startRatelimit, api, nil)
}

// MountPlaneARoutesWithHeal is MountPlaneARoutes plus an optional reverse-share
// wait opener wrapped around the session poll route. A nil opener keeps the
// poll a plain read.
func MountPlaneARoutesWithHeal(
	r chi.Router,
	h *Handler,
	startRatelimit func(http.Handler) http.Handler,
	api PlaneAAPIRoutePatterns,
	reverseWaitOpen ReverseWaitOpener,
) {
	start := CreateSessionRouteSpec()
	stop := StopSessionRouteSpec()

	mountRateLimited(r, startRatelimit, start.Method, start.Pattern, http.HandlerFunc(h.HandleStart))

	sessionHandler := http.HandlerFunc(h.HandleSession)
	if reverseWaitOpen != nil {
		sessionHandler = healReverseWaitOnPoll(h.store, h.log, reverseWaitOpen, sessionHandler)
	}

	r.Method(stop.Method, stop.Pattern, http.HandlerFunc(h.HandleStop))

	claim := ClaimInviteRouteSpec()
	mountRateLimited(r, startRatelimit, claim.Method, claim.Pattern, http.HandlerFunc(h.HandleClaimInvite))
	r.Method(http.MethodGet, api.Scan, http.HandlerFunc(h.HandleScan))
	r.Method(http.MethodGet, api.Session, sessionHandler)
	r.Method(http.MethodGet, api.Manifest, http.HandlerFunc(h.HandleManifest))
	r.Method(http.MethodGet, api.Statistics, http.HandlerFunc(h.HandleStatistics))
	r.Method(http.MethodGet, api.Report, http.HandlerFunc(h.HandleReportJSON))
	r.Method(http.MethodPatch, RouteAPIReportRetention, http.HandlerFunc(h.HandleReportRetention))
	r.Method(http.MethodPost, RouteAPIReportLock, http.HandlerFunc(h.HandleReportLock))
}

// EnumeratePlaneARoutes walks a chi router mounted via MountPlaneARoutes and
// returns full /validator/... route inventory for manifest drift checks.
func EnumeratePlaneARoutes(r chi.Router) ([]MountedAPIRoute, error) {
	routes := make([]MountedAPIRoute, 0, 16)

	err := chi.Walk(r, func(method, pattern string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if !isPlaneAEnumeratedPattern(pattern) {
			return nil
		}

		routes = append(routes, MountedAPIRoute{
			Method:   method,
			FullPath: serviceRelativeToFullPath(pattern),
		})

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk plane-A routes: %w", err)
	}

	return routes, nil
}

func mountRateLimited(
	r chi.Router,
	startRatelimit func(http.Handler) http.Handler,
	method, pattern string,
	handler http.Handler,
) {
	if startRatelimit != nil {
		r.With(startRatelimit).Method(method, pattern, handler)

		return
	}

	r.Method(method, pattern, handler)
}

func serviceRelativeToFullPath(pattern string) string {
	return joinReportPath("", manifestServicePrefix, pattern)
}

func isPlaneAEnumeratedPattern(pattern string) bool {
	trimmed := strings.Trim(pattern, "/")
	if trimmed == "start" || trimmed == "stop" {
		return true
	}

	return strings.HasPrefix(trimmed, "api/")
}
