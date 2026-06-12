// Package webdav provides the /webdav/* endpoints as a registry service.
package webdav

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/webdav"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	svccfg "github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service/cfg"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service/httpwrap"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
)

// Config holds webdav service configuration (service-local knobs only).
type Config struct{}

// ApplyDefaults implements cfg.Setter.
func (c *Config) ApplyDefaults() {}

// Service is the WebDAV service.
type Service struct {
	router  chi.Router
	conf    *Config
	log     *slog.Logger
	handler *webdav.Handler
}

// New creates a new WebDAV service from narrow injected inputs.
func New(inputs Inputs, m map[string]any, log *slog.Logger) (service.Service, error) {
	log = logutil.NoopIfNil(log)

	var c Config
	unused, err := svccfg.DecodeWithUnused(m, &c)
	if err != nil {
		return nil, err
	}
	if len(unused) > 0 {
		log.Warn("unused config keys", "service", "webdav", "unused_keys", unused)
	}

	handler := webdav.NewHandler(
		inputs.OutgoingShareRepo,
		inputs.TokenStore,
		inputs.PeerContract,
		log.With("component", "webdav"),
	)

	r := chi.NewRouter()
	r.HandleFunc("/ocm/*", handler.ServeHTTP)

	return &Service{router: r, conf: &c, log: log, handler: handler}, nil
}

func (s *Service) Handler() http.Handler {
	return httpwrap.ClearRawPath(s.router)
}

func (s *Service) Prefix() string {
	return "webdav"
}

func (s *Service) Unprotected() []string {
	return []string{"/ocm"}
}

func (s *Service) Close() error {
	return nil
}
