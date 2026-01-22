// Package uiservice provides the /ui/* endpoints as a registry service.
package uiservice

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	svccfg "github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service/cfg"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/deps"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service/httpwrap"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/ui"
)

func init() {
	service.MustRegister("uiservice", New)
}

// Config holds uiservice configuration.
type Config struct {
	ExternalBasePath string `mapstructure:"external_base_path"`
}

// ApplyDefaults implements cfg.Setter.
func (c *Config) ApplyDefaults() {}

// Service is the UI service.
type Service struct {
	router chi.Router
	conf   *Config
	log    *slog.Logger
}

// New creates a new UI service.
func New(m map[string]any, log *slog.Logger) (service.Service, error) {
	var c Config
	unused, err := svccfg.DecodeWithUnused(m, &c)
	if err != nil {
		return nil, err
	}
	if len(unused) > 0 {
		log.Warn("unused config keys", "service", "uiservice", "unused_keys", unused)
	}

	d := deps.GetDeps()
	if d == nil {
		return nil, errors.New("shared deps not initialized")
	}
	_ = d // deps available for future use

	// Create UI handler (templates are embedded in the ui package)
	uiHandler, err := ui.NewHandler(c.ExternalBasePath)
	if err != nil {
		return nil, err
	}

	r := chi.NewRouter()
	r.Get("/login", uiHandler.Login) // public
	r.Get("/inbox", uiHandler.Inbox) // session-gated

	return &Service{router: r, conf: &c, log: log}, nil
}

// Handler returns the service's HTTP handler with RawPath clearing.
func (s *Service) Handler() http.Handler {
	return httpwrap.ClearRawPath(s.router)
}

// Prefix returns the URL prefix for this service.
func (s *Service) Prefix() string {
	return "ui"
}

// Unprotected returns paths that don't require session authentication.
func (s *Service) Unprotected() []string {
	return []string{"/login"}
}

// Close releases any resources held by the service.
func (s *Service) Close() error {
	return nil
}
