// Package webdavservice provides the /webdav/* endpoints as a registry service.
package webdavservice

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/services"
	svccfg "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/cfg"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/services/httpwrap"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/webdav"
)

func init() {
	service.MustRegister("webdavservice", New)
}

// Config holds webdavservice configuration.
type Config struct {
	WebDAVTokenExchangeMode string `mapstructure:"webdav_token_exchange_mode"`
}

// ApplyDefaults implements cfg.Setter.
func (c *Config) ApplyDefaults() {
	if c.WebDAVTokenExchangeMode == "" {
		c.WebDAVTokenExchangeMode = "strict"
	}
}

// Service is the WebDAV service.
type Service struct {
	router  chi.Router
	conf    *Config
	log     *slog.Logger
	handler *webdav.Handler
}

// New creates a new WebDAV service.
func New(m map[string]any, log *slog.Logger) (service.Service, error) {
	var c Config
	unused, err := svccfg.DecodeWithUnused(m, &c)
	if err != nil {
		return nil, err
	}
	if len(unused) > 0 {
		log.Warn("unused config keys", "service", "webdavservice", "unused_keys", unused)
	}

	deps := services.GetDeps()
	if deps == nil {
		return nil, errors.New("shared deps not initialized")
	}

	// Create WebDAV settings
	settings := &webdav.Settings{
		WebDAVTokenExchangeMode: c.WebDAVTokenExchangeMode,
	}
	settings.ApplyDefaults()

	// Create WebDAV handler with ProfileRegistry for peer relaxations
	handler := webdav.NewHandler(
		deps.OutgoingShareRepo,
		deps.TokenStore,
		settings,
		deps.ProfileRegistry,
		log.With("component", "webdav"),
	)

	r := chi.NewRouter()
	// Mount WebDAV handler for all OCM share paths
	r.HandleFunc("/ocm/*", handler.ServeHTTP)

	return &Service{router: r, conf: &c, log: log, handler: handler}, nil
}

// Handler returns the service's HTTP handler with RawPath clearing.
func (s *Service) Handler() http.Handler {
	return httpwrap.ClearRawPath(s.router)
}

// Prefix returns the URL prefix for this service.
func (s *Service) Prefix() string {
	return "webdav"
}

// Unprotected returns paths that don't require session authentication.
// WebDAV OCM endpoints use Bearer/Basic auth, not session auth.
func (s *Service) Unprotected() []string {
	return []string{"/ocm"}
}

// Close releases any resources held by the service.
func (s *Service) Close() error {
	return nil
}
