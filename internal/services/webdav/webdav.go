// Package webdav provides the /webdav/* endpoints as a registry service.
package webdav

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/webdav"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	svccfg "github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service/cfg"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service/httpwrap"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/deps"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
)

func init() {
	service.MustRegister("webdav", New)
}

// Config holds webdav service configuration.
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
	log = logutil.NoopIfNil(log)

	var c Config
	unused, err := svccfg.DecodeWithUnused(m, &c)
	if err != nil {
		return nil, err
	}
	if len(unused) > 0 {
		log.Warn("unused config keys", "service", "webdav", "unused_keys", unused)
	}

	d := deps.GetDeps()
	if d == nil {
		return nil, errors.New("shared deps not initialized")
	}

	// Create WebDAV settings
	settings := &webdav.Settings{
		WebDAVTokenExchangeMode: c.WebDAVTokenExchangeMode,
	}
	settings.ApplyDefaults()

	// Create WebDAV handler with ProfileRegistry for peer relaxations
	handler := webdav.NewHandler(
		d.OutgoingShareRepo,
		d.TokenStore,
		settings,
		d.ProfileRegistry,
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
