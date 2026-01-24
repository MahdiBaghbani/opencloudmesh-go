// Package ocmaux provides OCM auxiliary endpoints (WAYF helpers).
package ocmaux

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federation"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	svccfg "github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service/cfg"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service/httpwrap"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/interceptors"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/deps"
)

func init() {
	service.MustRegister("ocmaux", New)
}

// Config holds ocmaux service configuration.
type Config struct {
	// Ratelimit holds rate limiting configuration for this service.
	Ratelimit RatelimitConfig `mapstructure:"ratelimit"`
}

// RatelimitConfig holds the per-service rate limiting opt-in.
type RatelimitConfig struct {
	// Profile is the name of the ratelimit profile to use from
	// [http.interceptors.ratelimit.profiles.<name>].
	Profile string `mapstructure:"profile"`
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

	d := deps.GetDeps()
	if d == nil {
		return nil, errors.New("shared deps not initialized")
	}

	// Create aux handler using SharedDeps
	auxHandler := federation.NewAuxHandler(d.FederationMgr, d.DiscoveryClient)

	// Build ratelimit middleware for /discover if profile is configured
	var discoverMiddleware func(http.Handler) http.Handler
	if c.Ratelimit.Profile != "" {
		profileConfig, err := interceptors.GetProfileConfig(d.Config.HTTP.Interceptors, "ratelimit", c.Ratelimit.Profile)
		if err != nil {
			return nil, fmt.Errorf("ocmaux: %w", err)
		}
		newInterceptor, ok := interceptors.Get("ratelimit")
		if !ok {
			return nil, errors.New("ocmaux: ratelimit interceptor not registered")
		}
		discoverMiddleware, err = newInterceptor(profileConfig, log)
		if err != nil {
			return nil, fmt.Errorf("ocmaux: failed to create ratelimit interceptor: %w", err)
		}
	}

	r := chi.NewRouter()
	r.Get("/federations", auxHandler.HandleFederations)

	// Apply ratelimit middleware only to /discover
	if discoverMiddleware != nil {
		r.With(discoverMiddleware).Get("/discover", auxHandler.HandleDiscover)
	} else {
		r.Get("/discover", auxHandler.HandleDiscover)
	}

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
// All ocm-aux endpoints are public (rate limiting is applied service-locally).
func (s *Service) Unprotected() []string {
	return []string{"/federations", "/discover"}
}

// Close releases any resources held by the service.
func (s *Service) Close() error {
	return nil
}
