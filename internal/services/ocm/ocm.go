// Package ocm provides the OCM protocol service for OpenCloudMesh.
// This service handles all /ocm/* endpoints including shares, notifications,
// invite-accepted, and token exchange.
package ocm

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	invitesincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/incoming"
	notifincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/notifications/incoming"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peer"
	sharesincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/incoming"
	tokenincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token/incoming"
	svccfg "github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service/cfg"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service/httpwrap"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/deps"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
)

func init() {
	service.MustRegister("ocm", New)
}

// Config holds OCM service configuration.
type Config struct {
	TokenExchange tokenincoming.TokenExchangeSettings `mapstructure:"token_exchange"`
}

// ApplyDefaults sets default values for unset fields.
func (c *Config) ApplyDefaults() {
	c.TokenExchange.ApplyDefaults()
}

// Service is the OCM protocol service.
// It implements service.Service and provides handlers for /ocm/* endpoints.
// The service owns signature middleware application internally (Reva-aligned).
type Service struct {
	router        chi.Router
	conf          *Config
	log           *slog.Logger
	tokenSettings *tokenincoming.TokenExchangeSettings // kept for Unprotected() computation
}

// New creates a new OCM protocol service.
// Implements service.NewService signature.
func New(m map[string]any, log *slog.Logger) (service.Service, error) {
	log = logutil.NoopIfNil(log)

	var c Config
	unused, err := svccfg.DecodeWithUnused(m, &c)
	if err != nil {
		return nil, err
	}
	if len(unused) > 0 {
		log.Warn("unused config keys", "service", "ocm", "unused_keys", unused)
	}

	d := deps.GetDeps()
	if d == nil {
		return nil, errors.New("shared deps not initialized: call deps.SetDeps() before New()")
	}

	// Derive token exchange from global config when not explicitly set in TOML.
	if d.Config != nil {
		var rawTE map[string]any
		if te, ok := m["token_exchange"].(map[string]any); ok {
			rawTE = te
		}
		if _, set := rawTE["enabled"]; !set {
			c.TokenExchange.Enabled = d.Config.TokenExchangeEnabled()
		}
		if _, set := rawTE["path"]; !set {
			c.TokenExchange.Path = d.Config.TokenExchange.Path
			if c.TokenExchange.Path == "" {
				c.TokenExchange.Path = "token"
			}
		}
	}

	if err := c.TokenExchange.Validate(); err != nil {
		return nil, err
	}

	// Construct handlers using SharedDeps (Reva-aligned)
	sharesHandler := sharesincoming.NewHandler(
		d.IncomingShareRepo,
		d.PartyRepo,
		d.PolicyEngine,
		d.LocalProviderFQDNForCompare,
		d.Config.PublicScheme(),
		d.Config.Signature.InboundMode,
		log,
	)
	notifHandler := notifincoming.NewHandler(d.OutgoingShareRepo, d.Config.PublicOrigin, log)
	invitesHandler := invitesincoming.NewHandler(d.OutgoingInviteRepo, d.PartyRepo, d.PolicyEngine, d.LocalProviderFQDN, d.Config.PublicOrigin, log)
	tokenHandler := tokenincoming.NewHandler(d.OutgoingShareRepo, d.TokenStore, &c.TokenExchange, d.Config.PublicOrigin, log)

	// Create peer resolver for signature verification (service-local, per-endpoint extraction)
	peerResolver := peer.NewResolver()

	// Build router with handlers
	// Apply signature middleware internally (Reva-aligned: service owns signature verification)
	r := chi.NewRouter()

	if d.SignatureMiddleware != nil {
		// Signed OCM endpoints - apply per-endpoint signature verification
		r.With(d.SignatureMiddleware.VerifyOCMRequest(peerResolver.ResolveSharesRequest)).
			Post("/shares", sharesHandler.CreateShare)
		r.With(d.SignatureMiddleware.VerifyOCMRequest(peerResolver.ResolveNotificationsRequest)).
			Post("/notifications", notifHandler.HandleNotification)
		r.With(d.SignatureMiddleware.VerifyOCMRequest(peerResolver.ResolveInviteAcceptedRequest)).
			Post("/invite-accepted", invitesHandler.HandleInviteAccepted)
		r.With(d.SignatureMiddleware.VerifyOCMRequest(peerResolver.ResolveTokenRequest)).
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
