// Package wellknown provides the OCM discovery service.
// This matches Reva's internal/http/services/wellknown/ structure.
package wellknown

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"log/slog"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/services"
	svccfg "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/cfg"
)

func init() {
	services.MustRegister("wellknown", New)
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

// New creates a new wellknown service. Implements services.NewService.
func New(m map[string]any, log *slog.Logger) (services.Service, error) {
	var c Config
	if err := svccfg.Decode(m, &c); err != nil {
		return nil, err
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
	s.router.Get("/.well-known/ocm", handler.ServeHTTP)
	s.router.Get("/ocm-provider", handler.ServeHTTP)
	return nil
}

// Close implements services.Service.
func (s *svc) Close() error { return nil }

// Prefix implements services.Service.
// Wellknown mounts at root (empty prefix).
func (s *svc) Prefix() string { return "" }

// Unprotected implements services.Service.
func (s *svc) Unprotected() []string {
	return []string{"/.well-known/ocm", "/ocm-provider"}
}

// Handler implements services.Service.
func (s *svc) Handler() http.Handler { return s.router }
