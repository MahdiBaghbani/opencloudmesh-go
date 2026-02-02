// Package ui provides the /ui/* endpoints as a registry service.
package ui

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ui"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	svccfg "github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service/cfg"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service/httpwrap"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/deps"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
)

func init() {
	service.MustRegister("ui", New)
}

// Config holds ui service configuration (service-local knobs only).
type Config struct {
	Wayf WayfConfig `mapstructure:"wayf"`
}

// WayfConfig holds WAYF (Where Are You From) UI configuration.
type WayfConfig struct {
	Enabled bool `mapstructure:"enabled"`
}

// ApplyDefaults implements cfg.Setter.
func (c *Config) ApplyDefaults() {}

// Service is the UI service.
type Service struct {
	router      chi.Router
	conf        *Config
	log         *slog.Logger
	wayfEnabled bool
}

// New creates a new UI service.
func New(m map[string]any, log *slog.Logger) (service.Service, error) {
	log = logutil.NoopIfNil(log)

	var c Config
	unused, err := svccfg.DecodeWithUnused(m, &c)
	if err != nil {
		return nil, err
	}
	if len(unused) > 0 {
		log.Warn("unused config keys", "service", "ui", "unused_keys", unused)
	}

	d := deps.GetDeps()
	if d == nil {
		return nil, errors.New("shared deps not initialized")
	}

	// Derive cross-cutting values from global config
	basePath := ""
	providerDomain := ""
	if d.Config != nil {
		basePath = d.Config.ExternalBasePath
	}
	providerDomain = d.LocalProviderFQDN

	// Create UI handler (templates are embedded in the ui package)
	uiHandler, err := ui.NewHandler(basePath, c.Wayf.Enabled, providerDomain)
	if err != nil {
		return nil, err
	}

	r := chi.NewRouter()
	r.Get("/login", uiHandler.Login) // public
	r.Get("/inbox", uiHandler.Inbox) // session-gated

	// WAYF routes: registered only when enabled (conditional registration)
	if c.Wayf.Enabled {
		r.Get("/wayf", uiHandler.Wayf)                 // public
		r.Get("/accept-invite", uiHandler.AcceptInvite) // session gated by auth middleware
		log.Info("WAYF UI enabled", "wayf_path", "/ui/wayf", "accept_invite_path", "/ui/accept-invite")
	}

	return &Service{router: r, conf: &c, log: log, wayfEnabled: c.Wayf.Enabled}, nil
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
	if s.wayfEnabled {
		// /wayf is a public guest page.
		return []string{"/login", "/wayf"}
	}
	return []string{"/login"}
}

// Close releases any resources held by the service.
func (s *Service) Close() error {
	return nil
}
