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
	{Name: "ocm-api", PathPrefix: "/ocm", RequiresAuth: false, AtHostRoot: false},       // OCM spec endpoints
	{Name: "ocm-aux", PathPrefix: "/ocm-aux", RequiresAuth: false, AtHostRoot: false},   // Helper endpoints (WAYF, etc)
	{Name: "api", PathPrefix: "/api", RequiresAuth: false, AtHostRoot: false},           // Mixed auth (healthz public, others protected)
	{Name: "ui", PathPrefix: "/ui", RequiresAuth: false, AtHostRoot: false},             // Mixed auth (login public, others protected)
	{Name: "webdav", PathPrefix: "/webdav/ocm", RequiresAuth: true, AtHostRoot: false},  // Bearer token auth
}

// GetRouteGroups returns the route group definitions for testing.
func GetRouteGroups() []RouteGroup {
	return routeGroups
}

// IsAuthRequired checks if a given path requires authentication.
// This is used by the auth middleware to make gating decisions.
func IsAuthRequired(path string, basePath string) bool {
	// Check root-only endpoints first
	for _, rg := range routeGroups {
		if rg.AtHostRoot {
			if path == rg.PathPrefix || (len(path) > len(rg.PathPrefix) && path[:len(rg.PathPrefix)+1] == rg.PathPrefix+"/") {
				return rg.RequiresAuth
			}
		}
	}

	// Check base-path-mounted endpoints
	for _, rg := range routeGroups {
		if !rg.AtHostRoot {
			fullPrefix := basePath + rg.PathPrefix
			if path == fullPrefix || (len(path) > len(fullPrefix) && path[:len(fullPrefix)+1] == fullPrefix+"/") {
				return rg.RequiresAuth
			}
		}
	}

	// Default: require auth for unknown paths
	return true
}

// setupRoutes creates the chi router with all route groups mounted.
func (s *Server) setupRoutes() chi.Router {
	r := chi.NewRouter()

	// Global middleware stack
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(s.loggingMiddleware)

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
	// Discovery endpoints (Phase A)
	r.Get("/.well-known/ocm", s.discoveryHandler.WellKnownHandler())
	// Legacy endpoint redirects to canonical well-known location
	r.Get("/ocm-provider", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/.well-known/ocm", http.StatusMovedPermanently)
	})
}

// mountAppEndpoints mounts app endpoints (may be under base path).
func (s *Server) mountAppEndpoints(r chi.Router) {
	// OCM API endpoints
	r.Route("/ocm", func(r chi.Router) {
		r.Post("/shares", s.sharesHandler.HandleCreate)
		r.Post("/notifications", s.notificationsHandler.HandleNotification)
		r.Post("/invite-accepted", s.invitesHandler.HandleInviteAccepted)
		r.Post("/token", s.tokenHandler.HandleToken)
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
