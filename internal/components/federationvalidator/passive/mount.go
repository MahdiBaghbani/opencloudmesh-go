// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// PlaneAAPIRoutePatterns holds service-relative GET /api/* patterns for plane-A.
type PlaneAAPIRoutePatterns struct {
	Scan       string
	Session    string
	Manifest   string
	Statistics string
}

// MountPlaneARoutes registers plane-A validator routes on r. startRatelimit may be
// nil to skip the POST /start ratelimit wrapper.
func MountPlaneARoutes(
	r chi.Router,
	h *Handler,
	startRatelimit func(http.Handler) http.Handler,
	api PlaneAAPIRoutePatterns,
) {
	start := CreateSessionRouteSpec()
	stop := StopSessionRouteSpec()

	if startRatelimit != nil {
		r.With(startRatelimit).Method(start.Method, start.Pattern, http.HandlerFunc(h.HandleStart))
	} else {
		r.Method(start.Method, start.Pattern, http.HandlerFunc(h.HandleStart))
	}

	r.Method(stop.Method, stop.Pattern, http.HandlerFunc(h.HandleStop))
	r.Method(http.MethodGet, api.Scan, http.HandlerFunc(h.HandleScan))
	r.Method(http.MethodGet, api.Session, http.HandlerFunc(h.HandleSession))
	r.Method(http.MethodGet, api.Manifest, http.HandlerFunc(h.HandleManifest))
	r.Method(http.MethodGet, api.Statistics, http.HandlerFunc(h.HandleStatistics))
}

// EnumeratePlaneARoutes walks a chi router mounted via MountPlaneARoutes and
// returns full /validator/... route inventory for manifest drift checks.
func EnumeratePlaneARoutes(r chi.Router) ([]MountedAPIRoute, error) {
	routes := make([]MountedAPIRoute, 0, 6)

	err := chi.Walk(r, func(method, pattern string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
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

func serviceRelativeToFullPath(pattern string) string {
	return "/" + manifestServicePrefix + pattern
}
