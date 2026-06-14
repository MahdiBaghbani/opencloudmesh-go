package wellknown

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery/resolve"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	svccfg "github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service/cfg"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service/httpwrap"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
)

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

// New creates a new wellknown service from narrow injected inputs.
func New(inputs Inputs, m map[string]any, log *slog.Logger) (service.Service, error) {
	log = logutil.NoopIfNil(log)

	var c Config
	unused, err := svccfg.DecodeWithUnused(m, &c)
	if err != nil {
		return nil, err
	}
	if len(unused) > 0 {
		log.Warn("unused config keys", "service", "wellknown", "unused_keys", unused)
	}

	var rawOCMProvider map[string]any
	if om, ok := m["ocmprovider"].(map[string]any); ok {
		rawOCMProvider = om
	}

	r := chi.NewRouter()
	s := &svc{
		router: r,
		conf:   &c,
	}

	if err := s.routerInit(inputs.Resolve, rawOCMProvider, log); err != nil {
		return nil, err
	}

	return s, nil
}

func (s *svc) routerInit(in resolve.ResolveInputs, rawOCMProvider map[string]any, log *slog.Logger) error {
	handler, err := newOCMHandler(&s.conf.OCMProvider, rawOCMProvider, in, log)
	if err != nil {
		return err
	}
	s.router.Get(RouteWellKnownOCM, handler.ServeHTTP)
	s.router.Get(RouteOCMProvider, handler.ServeHTTP)
	s.router.Get(RouteWellKnownOCMSlash, handler.ServeHTTP)
	s.router.Get(RouteOCMProviderSlash, handler.ServeHTTP)
	return nil
}

// Close implements service.Service.
func (s *svc) Close() error { return nil }

// Prefix implements service.Service.
func (s *svc) Prefix() string { return "" }

// Handler implements service.Service.
func (s *svc) Handler() http.Handler { return httpwrap.ClearRawPath(s.router) }
