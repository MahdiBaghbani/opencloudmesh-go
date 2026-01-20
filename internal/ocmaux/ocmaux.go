// Package ocmaux provides OCM auxiliary endpoints (WAYF helpers).
package ocmaux

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/federation"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/services"
	svccfg "github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service/cfg"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service/httpwrap"
)

func init() {
	service.MustRegister("ocmaux", New)
}

// Config holds ocmaux service configuration.
type Config struct {
	// No config fields needed initially
}

// ApplyDefaults implements cfg.Setter.
func (c *Config) ApplyDefaults() {}

// Service is the ocm-aux service.
type Service struct {
	router chi.Router
	conf   *Config
	log    *slog.Logger
}

// New creates a new ocm-aux service.
func New(m map[string]any, log *slog.Logger) (service.Service, error) {
	var c Config
	unused, err := svccfg.DecodeWithUnused(m, &c)
	if err != nil {
		return nil, err
	}
	if len(unused) > 0 {
		log.Warn("unused config keys", "service", "ocmaux", "unused_keys", unused)
	}

	deps := services.GetDeps()
	if deps == nil {
		return nil, errors.New("shared deps not initialized")
	}

	// Create aux handler using SharedDeps
	auxHandler := federation.NewAuxHandler(deps.FederationMgr, deps.DiscoveryClient)

	r := chi.NewRouter()
	r.Get("/federations", auxHandler.HandleFederations)
	r.Get("/discover", auxHandler.HandleDiscover)

	return &Service{router: r, conf: &c, log: log}, nil
}

// Handler returns the service's HTTP handler with RawPath clearing.
func (s *Service) Handler() http.Handler {
	return httpwrap.ClearRawPath(s.router)
}

// Prefix returns the URL prefix for this service.
func (s *Service) Prefix() string {
	return "ocm-aux"
}

// Unprotected returns paths that don't require session authentication.
// All ocm-aux endpoints are public (rate limiting is applied by server).
func (s *Service) Unprotected() []string {
	return []string{"/federations", "/discover"}
}

// Close releases any resources held by the service.
func (s *Service) Close() error {
	return nil
}
