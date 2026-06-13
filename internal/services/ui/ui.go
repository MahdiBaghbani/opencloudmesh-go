// Package ui provides the /ui/* endpoints as a registry service.
package ui

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ui"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	svccfg "github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service/cfg"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service/httpwrap"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
)

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

// New creates a new UI service from narrow injected inputs.
func New(inputs Inputs, m map[string]any, log *slog.Logger) (service.Service, error) {
	log = logutil.NoopIfNil(log)

	var c Config
	unused, err := svccfg.DecodeWithUnused(m, &c)
	if err != nil {
		return nil, err
	}
	if len(unused) > 0 {
		log.Warn("unused config keys", "service", "ui", "unused_keys", unused)
	}

	uiHandler, err := ui.NewHandler(inputs.LocalIdentity.ExternalBasePath, c.Wayf.Enabled, inputs.LocalIdentity.ProviderDomain)
	if err != nil {
		return nil, err
	}

	r := chi.NewRouter()
	r.Get("/login", uiHandler.Login)
	r.Get("/inbox", uiHandler.Inbox)
	r.Get("/outgoing", uiHandler.Outgoing)

	if c.Wayf.Enabled {
		r.Get("/wayf", uiHandler.Wayf)
		r.Get("/accept-invite", uiHandler.AcceptInvite)
		log.Info("WAYF UI enabled", "wayf_path", "/ui/wayf", "accept_invite_path", "/ui/accept-invite")
	}

	return &Service{router: r, conf: &c, log: log, wayfEnabled: c.Wayf.Enabled}, nil
}

func (s *Service) Handler() http.Handler {
	return httpwrap.ClearRawPath(s.router)
}

func (s *Service) Prefix() string {
	return "ui"
}

func (s *Service) Unprotected() []string {
	if s.wayfEnabled {
		return []string{"/login", "/wayf"}
	}
	return []string{"/login"}
}

func (s *Service) Close() error {
	return nil
}
