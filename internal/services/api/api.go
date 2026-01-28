// Package api provides the /api/* endpoints.
package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/notifications"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	svccfg "github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service/cfg"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service/httpwrap"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/interceptors"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/deps"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/auth"
)

func init() {
	service.MustRegister("api", New)
}

// Config holds api service configuration.
type Config struct {
	// Ratelimit holds rate limiting configuration for this service.
	Ratelimit RatelimitConfig `mapstructure:"ratelimit"`
}

// RatelimitConfig holds the per-service rate limiting opt-in.
type RatelimitConfig struct {
	// Profile is the name of the ratelimit profile to use from
	// [http.interceptors.ratelimit.profiles.<name>].
	Profile string `mapstructure:"profile"`
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
func New(m map[string]any, log *slog.Logger) (service.Service, error) {
	var c Config
	unused, err := svccfg.DecodeWithUnused(m, &c)
	if err != nil {
		return nil, err
	}
	if len(unused) > 0 {
		log.Warn("unused config keys", "service", "api", "unused_keys", unused)
	}

	d := deps.GetDeps()
	if d == nil {
		return nil, errors.New("shared deps not initialized")
	}

	// Create handlers using SharedDeps
	authHandler := api.NewAuthHandler(d.PartyRepo, d.SessionRepo, d.UserAuth)
	inboxHandler := shares.NewInboxHandler(d.IncomingShareRepo)

	// Create notification client for outbound notifications
	notificationClient := notifications.NewClient(
		d.HTTPClient,
		d.DiscoveryClient,
		d.Signer,
		d.OutboundPolicy,
	)
	inboxActionsHandler := shares.NewInboxActionsHandler(d.IncomingShareRepo, notificationClient, log)

	// Create outgoing share handler
	outgoingHandler := shares.NewOutgoingHandler(
		d.OutgoingShareRepo,
		d.DiscoveryClient,
		d.HTTPClient,
		d.Signer,
		d.OutboundPolicy,
		d.Config,
		log,
	)

	// Create invites inbox handler
	invitesInboxHandler := invites.NewInboxHandler(
		d.IncomingInviteRepo,
		d.DiscoveryClient,
		d.HTTPClient,
		d.Signer,
		d.OutboundPolicy,
		"", // User ID set from session context
		d.LocalProviderFQDN,
		log,
	)

	// CurrentUser adapter for session-gated handlers
	currentUser := func(ctx context.Context) (*identity.User, error) {
		u := auth.GetUserFromContext(ctx)
		if u == nil {
			return nil, fmt.Errorf("no authenticated user in context")
		}
		return u, nil
	}

	// Create outgoing invites handler (local-user API, uses OCM invites package)
	outgoingInvitesHandler := invites.NewHandler(
		d.OutgoingInviteRepo,
		nil, // partyRepo not needed for HandleCreateOutgoing
		d.LocalProviderFQDN,
		d.Config.PublicOrigin,
		currentUser,
		log,
	)

	// Build ratelimit middleware for /auth/login if profile is configured
	var loginMiddleware func(http.Handler) http.Handler
	if c.Ratelimit.Profile != "" {
		profileConfig, err := interceptors.GetProfileConfig(d.Config.HTTP.Interceptors, "ratelimit", c.Ratelimit.Profile)
		if err != nil {
			return nil, fmt.Errorf("api: %w", err)
		}
		newInterceptor, ok := interceptors.Get("ratelimit")
		if !ok {
			return nil, errors.New("api: ratelimit interceptor not registered")
		}
		loginMiddleware, err = newInterceptor(profileConfig, log)
		if err != nil {
			return nil, fmt.Errorf("api: failed to create ratelimit interceptor: %w", err)
		}
	}

	r := chi.NewRouter()

	// Health endpoint (public)
	r.Get("/healthz", api.HealthHandler)

	// Auth endpoints
	r.Route("/auth", func(r chi.Router) {
		// Apply ratelimit middleware only to /login
		if loginMiddleware != nil {
			r.With(loginMiddleware).Post("/login", authHandler.Login)
		} else {
			r.Post("/login", authHandler.Login)
		}
		r.Post("/logout", authHandler.Logout)    // session
		r.Get("/me", authHandler.GetCurrentUser) // session
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
