// Package apiservice provides the /api/* endpoints.
package apiservice

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/api"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/ocm/invites"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/ocm/notifications"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/ocm/shares"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/services"
	svccfg "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/cfg"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/services/httpwrap"
)

func init() {
	services.MustRegister("apiservice", New)
}

// Config holds apiservice configuration.
type Config struct {
	ProviderFQDN string `mapstructure:"provider_fqdn"`
}

// ApplyDefaults implements cfg.Setter.
func (c *Config) ApplyDefaults() {}

// Service is the API service.
type Service struct {
	router chi.Router
	conf   *Config
	log    *slog.Logger
}

// New creates a new API service.
func New(m map[string]any, log *slog.Logger) (services.Service, error) {
	var c Config
	unused, err := svccfg.DecodeWithUnused(m, &c)
	if err != nil {
		return nil, err
	}
	if len(unused) > 0 {
		log.Warn("unused config keys", "service", "apiservice", "unused_keys", unused)
	}

	deps := services.GetDeps()
	if deps == nil {
		return nil, errors.New("shared deps not initialized")
	}

	// Create handlers using SharedDeps
	authHandler := api.NewAuthHandler(deps.PartyRepo, deps.SessionRepo, deps.UserAuth)
	inboxHandler := shares.NewInboxHandler(deps.IncomingShareRepo)

	// Create notification client for outbound notifications
	notificationClient := notifications.NewClient(
		deps.HTTPClient,
		deps.DiscoveryClient,
		deps.Signer,
		deps.OutboundPolicy,
	)
	inboxActionsHandler := shares.NewInboxActionsHandler(deps.IncomingShareRepo, notificationClient, log)

	// Create outgoing share handler
	outgoingHandler := shares.NewOutgoingHandler(
		deps.OutgoingShareRepo,
		deps.DiscoveryClient,
		deps.HTTPClient,
		deps.Signer,
		deps.OutboundPolicy,
		deps.Config,
		log,
	)

	// Create invites inbox handler
	invitesInboxHandler := invites.NewInboxHandler(
		deps.IncomingInviteRepo,
		deps.DiscoveryClient,
		deps.HTTPClient,
		deps.Signer,
		deps.OutboundPolicy,
		"", // User ID set from session context
		c.ProviderFQDN,
		log,
	)

	// Create outgoing invites handler (local-user API, uses OCM invites package)
	outgoingInvitesHandler := invites.NewHandler(
		deps.OutgoingInviteRepo,
		c.ProviderFQDN,
		log,
	)

	r := chi.NewRouter()

	// Health endpoint (public)
	r.Get("/healthz", api.HealthHandler)

	// Auth endpoints
	r.Route("/auth", func(r chi.Router) {
		r.Post("/login", authHandler.Login)       // public
		r.Post("/logout", authHandler.Logout)     // session
		r.Get("/me", authHandler.GetCurrentUser)  // session
	})

	// Inbox endpoints (session-gated)
	r.Route("/inbox", func(r chi.Router) {
		r.Get("/shares", inboxHandler.HandleList)
		r.Post("/shares/{shareId}/accept", inboxActionsHandler.HandleAccept)
		r.Post("/shares/{shareId}/decline", inboxActionsHandler.HandleDecline)
		r.Get("/invites", invitesInboxHandler.HandleList)
		r.Post("/invites/{inviteId}/accept", invitesInboxHandler.HandleAccept)
		r.Post("/invites/{inviteId}/decline", invitesInboxHandler.HandleDecline)
	})

	// Outgoing shares (session-gated)
	r.Route("/shares", func(r chi.Router) {
		r.Post("/outgoing", outgoingHandler.HandleCreate)
	})

	// Outgoing invites (session-gated) - local-user API, not OCM protocol
	r.Route("/invites", func(r chi.Router) {
		r.Post("/outgoing", outgoingInvitesHandler.HandleCreateOutgoing)
	})

	// Admin endpoints (session-gated)
	r.Route("/admin", func(r chi.Router) {
		r.Get("/federations", notImplementedHandler("admin-federations"))
	})

	return &Service{router: r, conf: &c, log: log}, nil
}

func notImplementedHandler(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		api.WriteNotImplemented(w, name)
	}
}

// Handler returns the service's HTTP handler with RawPath clearing.
func (s *Service) Handler() http.Handler {
	return httpwrap.ClearRawPath(s.router)
}

// Prefix returns the URL prefix for this service.
func (s *Service) Prefix() string {
	return "api"
}

// Unprotected returns paths that don't require session authentication.
func (s *Service) Unprotected() []string {
	return []string{"/healthz", "/auth/login"}
}

// Close releases any resources held by the service.
func (s *Service) Close() error {
	return nil
}
