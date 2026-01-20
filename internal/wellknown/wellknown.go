// Package wellknown provides the OCM discovery service.
// This matches Reva's internal/http/services/wellknown/ structure.
package wellknown

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/services"
	svccfg "github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service/cfg"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/services/httpwrap"
)

func init() {
	service.MustRegister("wellknown", New)
}

// Config holds wellknown service configuration.
type Config struct {
	OCMProvider OCMProviderConfig `mapstructure:"ocmprovider"`
}

// ApplyDefaults implements cfg.Setter.
func (c *Config) ApplyDefaults() {
	c.OCMProvider.ApplyDefaults()
}

type svc struct {
	router chi.Router
	conf   *Config
}

// New creates a new wellknown service. Implements service.NewService.
func New(m map[string]any, log *slog.Logger) (service.Service, error) {
	var c Config
	unused, err := svccfg.DecodeWithUnused(m, &c)
	if err != nil {
		return nil, err
	}
	if len(unused) > 0 {
		log.Warn("unused config keys", "service", "wellknown", "unused_keys", unused)
	}

	// Hard requirement: SharedDeps must be initialized before any service is constructed.
	deps := services.GetDeps()
	if deps == nil {
		return nil, errors.New("shared deps not initialized: call services.SetDeps() before New()")
	}

	r := chi.NewRouter()
	s := &svc{
		router: r,
		conf:   &c,
	}

	if err := s.routerInit(deps, log); err != nil {
		return nil, err
	}

	return s, nil
}

func (s *svc) routerInit(deps *services.Deps, log *slog.Logger) error {
	handler, err := newOCMHandler(&s.conf.OCMProvider, deps, log)
	if err != nil {
		return err
	}
	// Primary routes
	s.router.Get("/.well-known/ocm", handler.ServeHTTP)
	s.router.Get("/ocm-provider", handler.ServeHTTP)
	// Trailing-slash aliases (no redirect, avoid changing signature inputs)
	s.router.Get("/.well-known/ocm/", handler.ServeHTTP)
	s.router.Get("/ocm-provider/", handler.ServeHTTP)
	return nil
}

// Close implements service.Service.
func (s *svc) Close() error { return nil }

// Prefix implements service.Service.
// Wellknown mounts at root (empty prefix).
func (s *svc) Prefix() string { return "" }

// Unprotected implements service.Service.
func (s *svc) Unprotected() []string {
	return []string{"/.well-known/ocm", "/.well-known/ocm/", "/ocm-provider", "/ocm-provider/"}
}

// Handler implements service.Service.
// Wraps router with RawPath clearing to match Reva pattern and avoid chi routing
// mismatches on percent-encoded path segments.
func (s *svc) Handler() http.Handler { return httpwrap.ClearRawPath(s.router) }
