package server

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/api"
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
	{Name: "api", PathPrefix: "/api", RequiresAuth: true, AtHostRoot: false},            // API: auth required (exceptions in publicExceptions)
	{Name: "ui", PathPrefix: "/ui", RequiresAuth: true, AtHostRoot: false},              // UI: auth required (exceptions in publicExceptions)
	{Name: "webdav", PathPrefix: "/webdav/ocm", RequiresAuth: true, AtHostRoot: false},  // Bearer token auth
}

// GetRouteGroups returns the route group definitions for testing.
func GetRouteGroups() []RouteGroup {
	return routeGroups
}

// publicExceptions are specific paths that don't require auth within otherwise protected groups.
var publicExceptions = []string{
	"/api/healthz",
	"/api/auth/login",
	"/ui/login",
	"/ui/static",
}

// IsAuthRequired checks if a given path requires authentication.
// This is used by the auth middleware to make gating decisions.
func IsAuthRequired(path string, basePath string) bool {
	// Check root-only endpoints first
	for _, rg := range routeGroups {
		if rg.AtHostRoot {
			if pathMatchesPrefix(path, rg.PathPrefix) {
				return rg.RequiresAuth
			}
		}
	}

	// Check public exceptions (paths that are always public)
	for _, exc := range publicExceptions {
		fullExc := basePath + exc
		if pathMatchesPrefix(path, fullExc) {
			return false
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

	// Global middleware stack
	r.Use(middleware.RequestID)
	r.Use(middleware.Recoverer)
	r.Use(s.loggingMiddleware)

	// Rate limiting for high-risk public endpoints
	rateLimitConfig := map[string]RateLimitConfig{
		"/ocm-aux/discover": {RequestsPerMinute: 10, Burst: 2},
		"/api/auth/login":   {RequestsPerMinute: 5, Burst: 2},
	}
	r.Use(s.rateLimitMiddleware(rateLimitConfig))

	// Auth middleware for all routes (checks IsAuthRequired)
	r.Use(s.authMiddleware)

	// Mount root-only endpoints at host root
	s.mountRootOnlyEndpoints(r)

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

// mountRootOnlyEndpoints mounts endpoints that must be at host root.
func (s *Server) mountRootOnlyEndpoints(r chi.Router) {
	// Discovery endpoints - both return the same JSON payload (no redirect)
	r.Get("/.well-known/ocm", s.discoveryHandler.WellKnownHandler())
	r.Get("/ocm-provider", s.discoveryHandler.WellKnownHandler())
}

// mountAppEndpoints mounts app endpoints (may be under base path).
func (s *Server) mountAppEndpoints(r chi.Router) {
	// OCM API endpoints - with signature verification middleware
	r.Route("/ocm", func(r chi.Router) {
		// Apply signature verification middleware with appropriate peer resolver per endpoint
		r.With(s.signatureMiddleware.VerifyOCMRequest(s.peerResolver.ResolveSharesRequest)).
			Post("/shares", s.sharesHandler.HandleCreate)
		r.With(s.signatureMiddleware.VerifyOCMRequest(s.peerResolver.ResolveNotificationsRequest)).
			Post("/notifications", s.notificationsHandler.HandleNotification)
		r.With(s.signatureMiddleware.VerifyOCMRequest(s.peerResolver.ResolveInviteAcceptedRequest)).
			Post("/invite-accepted", s.invitesHandler.HandleInviteAccepted)
		r.With(s.signatureMiddleware.VerifyOCMRequest(s.peerResolver.ResolveTokenRequest)).
			Post("/token", s.tokenHandler.HandleToken)
	})

	// OCM auxiliary endpoints (WAYF helpers) - Phase B
	r.Route("/ocm-aux", func(r chi.Router) {
		r.Get("/federations", s.auxHandler.HandleFederations)
		r.Get("/discover", s.auxHandler.HandleDiscover)
	})

	// API endpoints
	r.Route("/api", func(r chi.Router) {
		// Health endpoint (public)
		r.Get("/healthz", api.HealthHandler)

		// Auth endpoints (public)
		r.Route("/auth", func(r chi.Router) {
			r.Post("/login", s.authHandler.Login)
			r.Post("/logout", s.authHandler.Logout)
			r.Get("/me", s.authHandler.GetCurrentUser)
		})

		// Inbox endpoints (authenticated)
		r.Route("/inbox", func(r chi.Router) {
			r.Get("/shares", s.inboxHandler.HandleList)
			r.Post("/shares/{shareId}/accept", s.inboxActionsHandler.HandleAccept)
			r.Post("/shares/{shareId}/decline", s.inboxActionsHandler.HandleDecline)
			r.Get("/invites", s.invitesInboxHandler.HandleList)
			r.Post("/invites/{inviteId}/accept", s.invitesInboxHandler.HandleAccept)
			r.Post("/invites/{inviteId}/decline", s.invitesInboxHandler.HandleDecline)
		})

		// Outgoing shares (authenticated)
		r.Route("/shares", func(r chi.Router) {
			r.Post("/outgoing", s.outgoingHandler.HandleCreate)
		})

		// Outgoing invites (authenticated)
		r.Route("/invites", func(r chi.Router) {
			r.Post("/outgoing", s.invitesHandler.HandleCreateOutgoing)
		})

		// Admin endpoints (authenticated)
		r.Route("/admin", func(r chi.Router) {
			r.Get("/federations", s.notImplementedHandler("admin-federations"))
		})
	})

	// UI endpoints
	r.Route("/ui", func(r chi.Router) {
		r.Get("/login", s.uiHandler.Login)
		r.Get("/inbox", s.uiHandler.Inbox)
	})

	// WebDAV endpoint - serves shared files
	r.Route("/webdav/ocm", func(r chi.Router) {
		r.HandleFunc("/*", s.webdavHandler.ServeHTTP)
	})
}

// notImplementedHandler returns a handler that responds with 501 Not Implemented.
func (s *Server) notImplementedHandler(name string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotImplemented)
		w.Write([]byte(`{"error":{"code":"not_implemented","reason_code":"endpoint_not_implemented","message":"` + name + ` not implemented yet"}}`))
	}
}
