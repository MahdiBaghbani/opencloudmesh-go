// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"fmt"
	"net/http"
	"slices"

	"github.com/go-chi/chi/v5"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/catalog"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
)

// MountPlaneARoutes registers catalog plane-A routes on r. startRatelimit may
// be nil to skip the shared wrapper on rate-limited catalog rows.
func MountPlaneARoutes(
	r chi.Router,
	h *Handler,
	startRatelimit func(http.Handler) http.Handler,
) {
	MountPlaneARoutesWithHeal(r, h, startRatelimit, nil)
}

// MountPlaneARoutesWithHeal is MountPlaneARoutes plus an optional reverse-share
// wait opener wrapped around the session poll route. A nil opener keeps the
// poll a plain read.
func MountPlaneARoutesWithHeal(
	r chi.Router,
	h *Handler,
	startRatelimit func(http.Handler) http.Handler,
	reverseWaitOpen ReverseWaitOpener,
) {
	caps := catalog.Caps{}
	if h != nil {
		caps = h.Caps()
	}

	handlers := planeAHandlers(h, reverseWaitOpen)

	for _, def := range catalog.Routes() {
		if !shouldMountPlaneA(def, caps) {
			continue
		}

		handler := handlers[def.ID]
		if handler == nil {
			continue
		}

		if usesRateLimit(def) {
			mountRateLimited(r, startRatelimit, def.Method, def.Pattern, handler)

			continue
		}

		r.Method(def.Method, def.Pattern, handler)
	}
}

// EnumeratePlaneARoutes walks a chi router mounted via MountPlaneARoutes and
// returns advertised /validator/... routes for manifest drift checks.
func EnumeratePlaneARoutes(r chi.Router) ([]MountedAPIRoute, error) {
	routes := make([]MountedAPIRoute, 0, 16)
	advertised := advertisedPatternSet()

	err := chi.Walk(r, func(method, pattern string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if _, ok := advertised[method+" "+pattern]; !ok {
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

// MountStartPage registers GET /start when the start page is in capability.
func MountStartPage(r chi.Router, h *Handler) {
	if h == nil || !h.Caps().ReverseInviteAvailable() {
		return
	}

	spec := StartPageRouteSpec()
	r.Method(spec.Method, spec.Pattern, http.HandlerFunc(h.HandleStartPage))
}

func shouldMountPlaneA(def catalog.RouteDef, caps catalog.Caps) bool {
	if def.ID == service.RouteIDValidatorHTMLStart ||
		def.ID == service.RouteIDValidatorHTMLReport ||
		def.ID == service.RouteIDValidatorAPISessionReverseInvite {
		return false
	}

	return def.ShouldMount(caps)
}

func usesRateLimit(def catalog.RouteDef) bool {
	return slices.Contains(def.Middleware, catalog.MiddlewareRateLimit)
}

func advertisedPatternSet() map[string]struct{} {
	set := make(map[string]struct{}, len(catalog.Routes()))

	for _, def := range catalog.Routes() {
		if def.Advertise {
			set[def.Method+" "+def.Pattern] = struct{}{}
		}
	}

	return set
}

func planeAHandlers(h *Handler, reverseWaitOpen ReverseWaitOpener) map[string]http.Handler {
	if h == nil {
		return map[string]http.Handler{}
	}

	sessionHandler := http.Handler(http.HandlerFunc(h.HandleSession))
	if reverseWaitOpen != nil {
		sessionHandler = healReverseWaitOnPoll(h.store, h.log, reverseWaitOpen, h.HandleSession)
	}

	return map[string]http.Handler{
		service.RouteIDValidatorStartCreateSession: http.HandlerFunc(h.HandleStart),
		service.RouteIDValidatorStopSession:        http.HandlerFunc(h.HandleStop),
		service.RouteIDValidatorAPIScan:            http.HandlerFunc(h.HandleScan),
		service.RouteIDValidatorAPISession:         sessionHandler,
		service.RouteIDValidatorAPISessionInvite:   http.HandlerFunc(h.HandleClaimInvite),
		service.RouteIDValidatorAPISessionAbort:    http.HandlerFunc(h.HandleAbort),
		service.RouteIDValidatorAPIManifest:        http.HandlerFunc(h.HandleManifest),
		service.RouteIDValidatorAPIStatistics:      http.HandlerFunc(h.HandleStatistics),
		service.RouteIDValidatorAPIReport:          http.HandlerFunc(h.HandleReportJSON),
		service.RouteIDValidatorAPIReportRetention: http.HandlerFunc(h.HandleReportRetention),
		service.RouteIDValidatorAPIReportLock:      http.HandlerFunc(h.HandleReportLock),
	}
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
	return catalog.JoinFullPath("", catalog.ServicePrefix, pattern)
}
