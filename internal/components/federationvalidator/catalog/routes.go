// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package catalog

import (
	"net/http"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
)

// Service-relative validator patterns. Passive and the validator service
// re-export these so route strings stay synchronized.
const (
	PatternStart        = "/start"
	PatternStop         = "/stop"
	PatternScan         = "/api/scan"
	PatternSession      = "/api/session/{id}"
	PatternClaim        = "/api/session/{id}/invite"
	PatternAbort        = "/api/session/{id}/abort"
	PatternPaste        = "/api/session/{id}/reverse-invite"
	PatternReportJSON   = "/api/report/{id}"
	PatternReportRetain = "/api/report/{id}/retention"
	PatternReportLock   = "/api/report/{id}/lock"
	PatternManifest     = "/api/manifest"
	PatternStatistics   = "/api/statistics"
	PatternHTMLReport   = "/report/{id}"
	ServicePrefix       = "validator"
	MiddlewareRateLimit = "ratelimit"
)

// MountWhen decides whether a route mounts for the given capabilities.
type MountWhen func(Caps) bool

// RouteDef is one catalog route: identity, pattern, and mount/advertisement
// metadata. RouteSpecs project from this type.
type RouteDef struct {
	ID          string
	Method      string
	Pattern     string
	HandlerAuth service.HandlerAuth
	Middleware  []string
	Surface     service.SurfaceClass
	Advertise   bool
	MountWhen   MountWhen
}

// Routes returns the validator route catalog in mount order.
func Routes() []RouteDef {
	return []RouteDef{
		rateLimitedAPI(
			service.RouteIDValidatorStartCreateSession,
			http.MethodPost,
			PatternStart,
			alwaysMounted,
		),
		uiRoute(
			service.RouteIDValidatorHTMLStart,
			http.MethodGet,
			PatternStart,
			whenReverseInvite,
			false,
		),
		plainAPI(
			service.RouteIDValidatorStopSession,
			http.MethodPost,
			PatternStop,
			alwaysMounted,
		),
		rateLimitedAPI(
			service.RouteIDValidatorAPIScan,
			http.MethodGet,
			PatternScan,
			whenReverseInvite,
		),
		plainAPI(
			service.RouteIDValidatorAPISession,
			http.MethodGet,
			PatternSession,
			alwaysMounted,
		),
		rateLimitedAPI(
			service.RouteIDValidatorAPISessionInvite,
			http.MethodPost,
			PatternClaim,
			whenReverseInvite,
		),
		plainAPI(
			service.RouteIDValidatorAPISessionAbort,
			http.MethodPost,
			PatternAbort,
			whenAbort,
		),
		plainAPI(
			service.RouteIDValidatorAPISessionReverseInvite,
			http.MethodPost,
			PatternPaste,
			whenReverseInvite,
		),
		plainAPI(
			service.RouteIDValidatorAPIReport,
			http.MethodGet,
			PatternReportJSON,
			alwaysMounted,
		),
		plainAPI(
			service.RouteIDValidatorAPIReportRetention,
			http.MethodPatch,
			PatternReportRetain,
			alwaysMounted,
		),
		plainAPI(
			service.RouteIDValidatorAPIReportLock,
			http.MethodPost,
			PatternReportLock,
			alwaysMounted,
		),
		uiRoute(
			service.RouteIDValidatorHTMLReport,
			http.MethodGet,
			PatternHTMLReport,
			alwaysMounted,
			false,
		),
		plainAPI(
			service.RouteIDValidatorAPIManifest,
			http.MethodGet,
			PatternManifest,
			alwaysMounted,
		),
		plainAPI(
			service.RouteIDValidatorAPIStatistics,
			http.MethodGet,
			PatternStatistics,
			alwaysMounted,
		),
	}
}

// ShouldMount reports whether def mounts under caps.
func (d RouteDef) ShouldMount(caps Caps) bool {
	if d.MountWhen == nil {
		return true
	}

	return d.MountWhen(caps)
}

// ToRouteSpec projects a catalog row onto the service route table.
func (d RouteDef) ToRouteSpec() service.RouteSpec {
	return service.RouteSpec{
		ID:               d.ID,
		Service:          string(service.BuildValidator),
		Method:           d.Method,
		Pattern:          d.Pattern,
		SessionPolicy:    service.SessionPublic,
		HandlerAuth:      d.HandlerAuth,
		Middleware:       append([]string(nil), d.Middleware...),
		SurfaceClass:     d.Surface,
		TrustClass:       service.TrustPeerNone,
		FeatureCondition: service.FeatureValidatorEnabled,
	}
}

// RouteSpecs projects the full catalog to service.RouteSpec rows.
func RouteSpecs() []service.RouteSpec {
	defs := Routes()
	specs := make([]service.RouteSpec, 0, len(defs))

	for _, def := range defs {
		specs = append(specs, def.ToRouteSpec())
	}

	return specs
}

// Lookup returns the catalog row for id, or false when unknown.
func Lookup(id string) (RouteDef, bool) {
	for _, def := range Routes() {
		if def.ID == id {
			return def, true
		}
	}

	return RouteDef{}, false
}

func alwaysMounted(Caps) bool { return true }

func whenReverseInvite(c Caps) bool { return c.ReverseInviteAvailable() }

func whenAbort(c Caps) bool { return c.Abort }

func rateLimitedAPI(id, method, pattern string, mount MountWhen) RouteDef {
	return RouteDef{
		ID:          id,
		Method:      method,
		Pattern:     pattern,
		HandlerAuth: service.HandlerAuthRateLimitOnly,
		Middleware:  []string{MiddlewareRateLimit},
		Surface:     service.SurfaceAPI,
		Advertise:   true,
		MountWhen:   mount,
	}
}

func plainAPI(id, method, pattern string, mount MountWhen) RouteDef {
	return RouteDef{
		ID:          id,
		Method:      method,
		Pattern:     pattern,
		HandlerAuth: service.HandlerAuthNone,
		Middleware:  []string{},
		Surface:     service.SurfaceAPI,
		Advertise:   true,
		MountWhen:   mount,
	}
}

func uiRoute(id, method, pattern string, mount MountWhen, advertise bool) RouteDef {
	return RouteDef{
		ID:          id,
		Method:      method,
		Pattern:     pattern,
		HandlerAuth: service.HandlerAuthNone,
		Middleware:  []string{},
		Surface:     service.SurfaceUI,
		Advertise:   advertise,
		MountWhen:   mount,
	}
}
