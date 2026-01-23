package server

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/deps"
)

// RouteGroup defines an endpoint group with its auth requirements.
type RouteGroup struct {
	Name         string
	PathPrefix   string
	RequiresAuth bool
	AtHostRoot   bool // true for endpoints that must be at host root, not under base path
}

// routeGroups defines all endpoint groups and their auth requirements.
// This table is the single source of truth for routing decisions.
var routeGroups = []RouteGroup{
	// Root-only endpoints (must be at host root, never under external_base_path)
	{Name: "well-known-ocm", PathPrefix: "/.well-known/ocm", RequiresAuth: false, AtHostRoot: true},
	{Name: "ocm-provider", PathPrefix: "/ocm-provider", RequiresAuth: false, AtHostRoot: true},

	// App endpoints (mounted under external_base_path)
	{Name: "ocm-api", PathPrefix: "/ocm", RequiresAuth: false, AtHostRoot: false},       // OCM spec endpoints (public for federation)
	{Name: "ocm-aux", PathPrefix: "/ocm-aux", RequiresAuth: false, AtHostRoot: false},   // Helper endpoints (rate-limited but public)
	{Name: "api", PathPrefix: "/api", RequiresAuth: true, AtHostRoot: false},            // API: auth required (exceptions via Service.Unprotected())
	{Name: "ui", PathPrefix: "/ui", RequiresAuth: true, AtHostRoot: false},              // UI: auth required (exceptions via Service.Unprotected())
	{Name: "webdav", PathPrefix: "/webdav/ocm", RequiresAuth: false, AtHostRoot: false}, // OCM WebDAV uses bearer/basic auth, not session
}

// GetRouteGroups returns the route group definitions for testing.
func GetRouteGroups() []RouteGroup {
	return routeGroups
}

// IsAuthRequired checks if a given path requires authentication.
// This is used by the auth middleware to make gating decisions.
// The mountedServices slice is used to compute unprotected paths from Service.Unprotected().
func IsAuthRequired(path string, basePath string, mountedServices []service.Service) bool {
	// Check root-only endpoints first
	for _, rg := range routeGroups {
		if rg.AtHostRoot {
			if pathMatchesPrefix(path, rg.PathPrefix) {
				return rg.RequiresAuth
			}
		}
	}

	// Compute unprotected paths from mounted services
	for _, svc := range mountedServices {
		if svc == nil {
			continue
		}
		// Build full service base path
		svcBase := basePath
		prefix := svc.Prefix()
		if prefix != "" {
			svcBase += "/" + prefix
		}
		// Check each unprotected path declared by the service
		for _, unprotected := range svc.Unprotected() {
			fullPath := svcBase + unprotected
			if pathMatchesPrefix(path, fullPath) {
				return false
			}
		}
	}

	// Check base-path-mounted endpoints
	for _, rg := range routeGroups {
		if !rg.AtHostRoot {
			fullPrefix := basePath + rg.PathPrefix
			if pathMatchesPrefix(path, fullPrefix) {
				return rg.RequiresAuth
			}
		}
	}

	// Default: require auth for unknown paths
	return true
}

// mountService mounts a service and tracks it for lifecycle management.
func (s *Server) mountService(r chi.Router, svc service.Service, atRoot bool) {
	if svc == nil {
		return
	}

	var handler http.Handler = svc.Handler()
	prefix := svc.Prefix()

	if atRoot || prefix == "" {
		r.Mount("/", handler)
	} else {
		r.Mount("/"+prefix, handler)
	}

	s.mountedServices = append(s.mountedServices, svc)
}

// pathMatchesPrefix checks if path equals or is a subpath of prefix.
func pathMatchesPrefix(path, prefix string) bool {
	if path == prefix {
		return true
	}
	if len(path) > len(prefix) && path[:len(prefix)] == prefix {
		// Check for path separator
		if path[len(prefix)] == '/' {
			return true
		}
	}
	return false
}

// setupRoutes creates the chi router with all route groups mounted.
func (s *Server) setupRoutes() chi.Router {
	r := chi.NewRouter()

	// Global middleware stack (order matters for correct logging)
	// RequestID must come first so GetReqID works in RequestLoggerMiddleware.
	// loggingMiddleware wraps response, Recoverer writes through wrapper,
	// so access log captures correct status for panics.
	r.Use(middleware.RequestID)
	r.Use(RequestLoggerMiddleware(s.logger, deps.GetDeps().RealIP))
	r.Use(s.loggingMiddleware)
	r.Use(middleware.Recoverer)

	// Rate limiting is now service-local (applied by ocmaux and apiservice).
	// The server-level limiter has been removed per Reva-aligned taxonomy refactor.

	// Auth middleware for all routes (checks IsAuthRequired)
	r.Use(s.authMiddleware)

	// Mount wellknown service at root (Reva-aligned)
	// This replaces the legacy mountRootOnlyEndpoints().
	s.mountService(r, s.wellknownSvc, true)

	// Mount app endpoints under external_base_path
	if s.cfg.ExternalBasePath != "" {
		r.Route(s.cfg.ExternalBasePath, func(r chi.Router) {
			s.mountAppEndpoints(r)
		})
	} else {
		s.mountAppEndpoints(r)
	}

	return r
}

// mountAppEndpoints mounts app endpoints (may be under base path).
func (s *Server) mountAppEndpoints(r chi.Router) {
	// OCM API endpoints - signature middleware is applied internally by the OCM service (Reva-aligned)
	s.mountService(r, s.ocmSvc, false)

	// OCM auxiliary endpoints (WAYF helpers)
	s.mountService(r, s.ocmauxSvc, false)

	// API endpoints
	s.mountService(r, s.apiserviceSvc, false)

	// UI endpoints
	s.mountService(r, s.uiserviceSvc, false)

	// WebDAV endpoints
	s.mountService(r, s.webdavserviceSvc, false)
}
