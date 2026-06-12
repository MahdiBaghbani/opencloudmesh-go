package server

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	httpmw "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/middleware"
)

// RouteGroup defines an endpoint group with its auth requirements.
type RouteGroup struct {
	Name         string
	PathPrefix   string
	RequiresAuth bool
	AtHostRoot   bool
}

var routeGroups = []RouteGroup{
	{Name: "well-known-ocm", PathPrefix: "/.well-known/ocm", RequiresAuth: false, AtHostRoot: true},
	{Name: "ocm-provider", PathPrefix: "/ocm-provider", RequiresAuth: false, AtHostRoot: true},
	{Name: "ocm-api", PathPrefix: "/ocm", RequiresAuth: false, AtHostRoot: false},
	{Name: "ocm-aux", PathPrefix: "/ocm-aux", RequiresAuth: false, AtHostRoot: false},
	{Name: "api", PathPrefix: "/api", RequiresAuth: true, AtHostRoot: false},
	{Name: "ui", PathPrefix: "/ui", RequiresAuth: true, AtHostRoot: false},
	{Name: "webdav", PathPrefix: "/webdav/ocm", RequiresAuth: false, AtHostRoot: false},
}

func GetRouteGroups() []RouteGroup {
	return routeGroups
}

func IsAuthRequired(path string, basePath string, mountedServices []service.Service) bool {
	for _, rg := range routeGroups {
		if rg.AtHostRoot {
			if pathMatchesPrefix(path, rg.PathPrefix) {
				return rg.RequiresAuth
			}
		}
	}

	for _, svc := range mountedServices {
		if svc == nil {
			continue
		}
		svcBase := basePath
		prefix := svc.Prefix()
		if prefix != "" {
			svcBase += "/" + prefix
		}
		for _, unprotected := range svc.Unprotected() {
			fullPath := svcBase + unprotected
			if pathMatchesPrefix(path, fullPath) {
				return false
			}
		}
	}

	for _, rg := range routeGroups {
		if !rg.AtHostRoot {
			fullPrefix := basePath + rg.PathPrefix
			if pathMatchesPrefix(path, fullPrefix) {
				return rg.RequiresAuth
			}
		}
	}

	return true
}

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

func pathMatchesPrefix(path, prefix string) bool {
	if path == prefix {
		return true
	}
	if len(path) > len(prefix) && path[:len(prefix)] == prefix {
		if path[len(prefix)] == '/' {
			return true
		}
	}
	return false
}

func (s *Server) setupRoutes() chi.Router {
	r := chi.NewRouter()

	r.Use(chimw.RequestID)
	r.Use(httpmw.RequestLoggerMiddleware(s.logger, s.deps.RealIP))
	r.Use(httpmw.AccessLogMiddleware(s.logger, s.deps.RealIP))
	r.Use(chimw.Recoverer)

	requireAuth := func(path string) bool {
		return IsAuthRequired(path, s.cfg.ExternalBasePath, s.mountedServices)
	}
	r.Use(s.deps.AuthGate(requireAuth))

	s.mountService(r, s.services[service.RootService], true)

	if s.cfg.ExternalBasePath != "" {
		r.Route(s.cfg.ExternalBasePath, func(r chi.Router) {
			s.mountAppEndpoints(r)
		})
	} else {
		s.mountAppEndpoints(r)
	}

	return r
}

func (s *Server) mountAppEndpoints(r chi.Router) {
	for _, name := range service.AppServices() {
		s.mountService(r, s.services[name], false)
	}
}
