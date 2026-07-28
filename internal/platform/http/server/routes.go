package server

import (
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

// GetMountSpecs returns the route groups derived from the default route options.
func GetMountSpecs() []RouteGroup {
	opts := service.DefaultRouteOpts()
	return mountSpecsFromDerived(opts)
}

func mountSpecsFromDerived(opts service.RouteOpts) []RouteGroup {
	specs := service.DerivedMountSpecs(opts)

	groups := make([]RouteGroup, len(specs))
	for i, spec := range specs {
		groups[i] = RouteGroup{
			Name:         spec.Name,
			PathPrefix:   spec.PathPrefix,
			RequiresAuth: spec.RequiresAuth,
			AtHostRoot:   spec.AtHostRoot,
		}
	}

	return groups
}

// IsAuthRequired reports whether the session auth gate requires authentication.
func IsAuthRequired(path string, opts service.RouteOpts) bool {
	return service.SessionAuthRequiredForPath(path, opts)
}

func (s *Server) mountService(r chi.Router, svc service.Service, atRoot bool) {
	if svc == nil {
		return
	}

	var handler = svc.Handler()

	prefix := svc.Prefix()

	if atRoot || prefix == "" {
		r.Mount("/", handler)
	} else {
		r.Mount("/"+prefix, handler)
	}

	s.mountedServices = append(s.mountedServices, svc)
}

func (s *Server) setupRoutes() chi.Router {
	r := chi.NewRouter()

	r.Use(chimw.RequestID)
	r.Use(httpmw.RequestLoggerMiddleware(s.logger, s.deps.RealIP))
	r.Use(httpmw.AccessLogMiddleware(s.logger, s.deps.RealIP))
	r.Use(chimw.Recoverer)

	routeOpts := service.RouteOptsFromConfig(s.cfg)
	authChecker := service.NewSessionAuthChecker(routeOpts)
	r.Use(s.deps.AuthGate(authChecker.Required))

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
