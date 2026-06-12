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
	inboxinvites "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api/inbox/invites"
	inboxshares "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api/inbox/shares"
	outgoinginvites "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api/outgoing/invites"
	outgoingshares "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api/outgoing/shares"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity/sessiongate"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/access"
	notifoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/notifications/outgoing"
	tokenoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	svccfg "github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service/cfg"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service/httpwrap"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/interceptors"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/interceptors/ratelimit"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
)

// Config holds api service configuration.
type Config struct {
	Ratelimit    RatelimitConfig `mapstructure:"ratelimit"`
	AllowedPaths []string        `mapstructure:"allowed_paths"`
}

// RatelimitConfig holds the per-service rate limiting opt-in.
type RatelimitConfig struct {
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

// New creates a new API service from narrow injected inputs.
func New(inputs Inputs, m map[string]any, log *slog.Logger) (service.Service, error) {
	log = logutil.NoopIfNil(log)

	if err := validateInputs(inputs); err != nil {
		return nil, err
	}

	var c Config
	unused, err := svccfg.DecodeWithUnused(m, &c)
	if err != nil {
		return nil, err
	}
	if len(unused) > 0 {
		log.Warn("unused config keys", "service", "api", "unused_keys", unused)
	}

	authHandler := api.NewAuthHandler(inputs.PartyRepo, inputs.SessionRepo, inputs.UserAuth)

	currentUser := func(ctx context.Context) (*identity.User, error) {
		u := sessiongate.GetUserFromContext(ctx)
		if u == nil {
			return nil, fmt.Errorf("no authenticated user in context")
		}
		return u, nil
	}

	notificationClient := notifoutgoing.NewClient(
		inputs.HTTPClient,
		inputs.DiscoveryClient,
		inputs.Signer,
		inputs.OutboundPolicy,
	)
	notificationClient.SetPeerContract(inputs.PeerContract)

	tokenClient := tokenoutgoing.NewClient(
		inputs.HTTPClient,
		inputs.DiscoveryClient,
		inputs.Signer,
		inputs.OutboundPolicy,
		inputs.LocalProviderFQDN,
	)
	accessClient := access.NewClient(
		inputs.HTTPClient,
		inputs.DiscoveryClient,
		tokenClient,
		inputs.PeerContract,
	)

	inboxSharesHandler := inboxshares.NewHandler(
		inputs.IncomingShareRepo,
		notificationClient,
		accessClient,
		currentUser,
		log,
	)

	outgoingHandler := outgoingshares.NewHandler(
		inputs.OutgoingShareRepo,
		inputs.DiscoveryClient,
		inputs.OpenCloudMeshPolicy,
		inputs.HTTPClient,
		inputs.Signer,
		inputs.OutboundPolicy,
		inputs.LocalProviderFQDN,
		currentUser,
		log,
	)
	outgoingHandler.SetPeerContract(inputs.PeerContract)
	if len(c.AllowedPaths) > 0 {
		outgoingHandler.SetAllowedPaths(c.AllowedPaths)
	}

	inboxInvitesHandler := inboxinvites.NewHandler(
		inputs.IncomingInviteRepo,
		inputs.HTTPClient,
		inputs.DiscoveryClient,
		inputs.Signer,
		inputs.OutboundPolicy,
		inputs.LocalProviderFQDN,
		currentUser,
		log,
	)
	inboxInvitesHandler.SetPeerContract(inputs.PeerContract)

	outgoingInvitesHandler := outgoinginvites.NewHandler(
		inputs.OutgoingInviteRepo,
		inputs.LocalProviderFQDN,
		currentUser,
		log,
	)

	var loginMiddleware func(http.Handler) http.Handler
	if c.Ratelimit.Profile != "" {
		profileConfig, err := interceptors.GetProfileConfig(inputs.InterceptorProfiles, "ratelimit", c.Ratelimit.Profile)
		if err != nil {
			return nil, fmt.Errorf("api: %w", err)
		}
		loginMiddleware, err = ratelimit.New(inputs.Ratelimit, profileConfig, log)
		if err != nil {
			return nil, fmt.Errorf("api: failed to create ratelimit interceptor: %w", err)
		}
	}

	r := chi.NewRouter()
	r.Get("/healthz", api.HealthHandler)

	r.Route("/auth", func(r chi.Router) {
		if loginMiddleware != nil {
			r.With(loginMiddleware).Post("/login", authHandler.Login)
		} else {
			r.Post("/login", authHandler.Login)
		}
		r.Post("/logout", authHandler.Logout)
		r.Get("/me", authHandler.GetCurrentUser)
	})

	r.Route("/inbox", func(r chi.Router) {
		r.Get("/shares", inboxSharesHandler.HandleList)
		r.Get("/shares/{shareId}", inboxSharesHandler.HandleGetDetail)
		r.Post("/shares/{shareId}/accept", inboxSharesHandler.HandleAccept)
		r.Post("/shares/{shareId}/decline", inboxSharesHandler.HandleDecline)
		r.Post("/shares/{shareId}/verify-access", inboxSharesHandler.HandleVerifyAccess)
		r.Get("/invites", inboxInvitesHandler.HandleList)
		r.Post("/invites/import", inboxInvitesHandler.HandleImport)
		r.Post("/invites/{inviteId}/accept", inboxInvitesHandler.HandleAccept)
		r.Post("/invites/{inviteId}/decline", inboxInvitesHandler.HandleDecline)
	})

	r.Route("/shares", func(r chi.Router) {
		r.Post("/outgoing", outgoingHandler.HandleCreate)
	})

	r.Route("/invites", func(r chi.Router) {
		r.Post("/outgoing", outgoingInvitesHandler.HandleCreateOutgoing)
	})

	r.Route("/admin", func(r chi.Router) {
		r.Get("/federations", notImplementedHandler("admin-federations"))
	})

	return &Service{router: r, conf: &c, log: log}, nil
}

func validateInputs(in Inputs) error {
	switch {
	case in.PartyRepo == nil:
		return errors.New("api: PartyRepo is required")
	case in.SessionRepo == nil:
		return errors.New("api: SessionRepo is required")
	case in.UserAuth == nil:
		return errors.New("api: UserAuth is required")
	case in.HTTPClient == nil:
		return errors.New("api: HTTPClient is required")
	case in.DiscoveryClient == nil:
		return errors.New("api: DiscoveryClient is required")
	case in.OpenCloudMeshPolicy == nil:
		return errors.New("api: OpenCloudMeshPolicy is required")
	default:
		return nil
	}
}

func notImplementedHandler(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		api.WriteNotImplemented(w, name)
	}
}

func (s *Service) Handler() http.Handler {
	return httpwrap.ClearRawPath(s.router)
}

func (s *Service) Prefix() string {
	return "api"
}

func (s *Service) Unprotected() []string {
	return []string{"/healthz", "/auth/login"}
}

func (s *Service) Close() error {
	return nil
}
