// Package ocm provides the OCM protocol service for OpenCloudMesh.
// This service handles all /ocm/* endpoints including shares, notifications,
// invite-accepted, and token exchange.
package ocm

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/crypto"
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
// The service owns signature middleware application internally (Reva-aligned).
type Service struct {
	router        chi.Router
	conf          *Config
	log           *slog.Logger
	tokenSettings *token.TokenExchangeSettings // kept for Unprotected() computation
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

	// Create peer resolver for signature verification (service-local, per-endpoint extraction)
	peerResolver := crypto.NewPeerResolver()

	// Build router with handlers
	// Apply signature middleware internally (Reva-aligned: service owns signature verification)
	r := chi.NewRouter()

	if deps.SignatureMiddleware != nil {
		// Signed OCM endpoints - apply per-endpoint signature verification
		r.With(deps.SignatureMiddleware.VerifyOCMRequest(peerResolver.ResolveSharesRequest)).
			Post("/shares", sharesHandler.CreateShare)
		r.With(deps.SignatureMiddleware.VerifyOCMRequest(peerResolver.ResolveNotificationsRequest)).
			Post("/notifications", notifHandler.HandleNotification)
		r.With(deps.SignatureMiddleware.VerifyOCMRequest(peerResolver.ResolveInviteAcceptedRequest)).
			Post("/invite-accepted", invitesHandler.HandleInviteAccepted)
		r.With(deps.SignatureMiddleware.VerifyOCMRequest(peerResolver.ResolveTokenRequest)).
			Post(c.TokenExchange.RoutePath(), tokenHandler.HandleToken)
	} else {
		// No signature verification (signature mode off)
		r.Post("/shares", sharesHandler.CreateShare)
		r.Post("/notifications", notifHandler.HandleNotification)
		r.Post("/invite-accepted", invitesHandler.HandleInviteAccepted)
		r.Post(c.TokenExchange.RoutePath(), tokenHandler.HandleToken)
	}

	return &Service{
		router:        r,
		conf:          &c,
		log:           log,
		tokenSettings: &c.TokenExchange,
	}, nil
}

// Handler returns the service's HTTP handler.
// Wraps router with RawPath clearing to match Reva pattern and avoid chi routing
// mismatches on percent-encoded path segments.
// Signature middleware is applied internally per endpoint (Reva-aligned).
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
		s.tokenSettings.RoutePath(),
	}
}

// Close releases any resources held by the service.
func (s *Service) Close() error {
	return nil
}
