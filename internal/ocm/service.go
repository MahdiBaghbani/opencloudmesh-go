// Package ocm provides the OCM protocol service for OpenCloudMesh.
// This service handles all /ocm/* endpoints including shares, notifications,
// invite-accepted, and token exchange.
package ocm

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/ocm/invites"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/ocm/notifications"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/ocm/shares"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/ocm/token"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/services"
	svccfg "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/cfg"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/services/httpwrap"
)

func init() {
	services.MustRegister("ocm", New)
}

// Config holds OCM service configuration.
type Config struct {
	TokenExchange token.TokenExchangeSettings `mapstructure:"token_exchange"`
	ProviderFQDN  string                      `mapstructure:"provider_fqdn"`
}

// ApplyDefaults sets default values for unset fields.
func (c *Config) ApplyDefaults() {
	c.TokenExchange.ApplyDefaults()
}

// Service is the OCM protocol service.
// It implements services.Service and provides handlers for /ocm/* endpoints.
type Service struct {
	router chi.Router
	conf   *Config
	log    *slog.Logger

	// Handlers are exposed for server to mount with signature middleware.
	// This is a hybrid pattern: handler construction is Reva-aligned (in service),
	// but route mounting with signature middleware stays in server layer.
	SharesHandler        *shares.IncomingHandler
	NotificationsHandler *notifications.Handler
	InvitesHandler       *invites.Handler
	TokenHandler         *token.Handler
	TokenSettings        *token.TokenExchangeSettings
}

// New creates a new OCM protocol service.
// Implements services.NewService signature.
func New(m map[string]any, log *slog.Logger) (services.Service, error) {
	var c Config
	unused, err := svccfg.DecodeWithUnused(m, &c)
	if err != nil {
		return nil, err
	}
	if len(unused) > 0 {
		log.Warn("unused config keys", "service", "ocm", "unused_keys", unused)
	}

	if err := c.TokenExchange.Validate(); err != nil {
		return nil, err
	}

	deps := services.GetDeps()
	if deps == nil {
		return nil, errors.New("shared deps not initialized: call services.SetDeps() before New()")
	}

	// Construct handlers using SharedDeps (Reva-aligned)
	sharesHandler := shares.NewIncomingHandler(deps.IncomingShareRepo, deps.PolicyEngine, log)
	notifHandler := notifications.NewHandler(deps.OutgoingShareRepo, log)
	invitesHandler := invites.NewHandler(deps.OutgoingInviteRepo, c.ProviderFQDN, log)
	tokenHandler := token.NewHandler(deps.OutgoingShareRepo, deps.TokenStore, &c.TokenExchange, log)

	// Build router with handlers (signature middleware applied by server at mount time)
	r := chi.NewRouter()
	r.Post("/shares", sharesHandler.CreateShare)
	r.Post("/notifications", notifHandler.HandleNotification)
	r.Post("/invite-accepted", invitesHandler.HandleInviteAccepted)
	r.Post(c.TokenExchange.RoutePath(), tokenHandler.HandleToken)

	return &Service{
		router:               r,
		conf:                 &c,
		log:                  log,
		SharesHandler:        sharesHandler,
		NotificationsHandler: notifHandler,
		InvitesHandler:       invitesHandler,
		TokenHandler:         tokenHandler,
		TokenSettings:        &c.TokenExchange,
	}, nil
}

// Handler returns the service's HTTP handler.
// Wraps router with RawPath clearing to match Reva pattern and avoid chi routing
// mismatches on percent-encoded path segments.
// Note: Signature middleware is applied by the server at mount time,
// not inside this handler. This is a hybrid pattern during migration.
func (s *Service) Handler() http.Handler {
	return httpwrap.ClearRawPath(s.router)
}

// Prefix returns the URL prefix for this service.
func (s *Service) Prefix() string {
	return "ocm"
}

// Unprotected returns paths that don't require session authentication.
// All OCM protocol endpoints are public (they use signature verification instead).
func (s *Service) Unprotected() []string {
	return []string{
		"/shares",
		"/notifications",
		"/invite-accepted",
		s.TokenSettings.RoutePath(),
	}
}

// Close releases any resources held by the service.
func (s *Service) Close() error {
	return nil
}
