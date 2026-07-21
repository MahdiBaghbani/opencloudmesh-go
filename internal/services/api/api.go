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

	tokenClient := tokenoutgoing.NewClient(
		inputs.HTTPClient,
		inputs.Signer,
		inputs.LocalIdentity.ProviderDomain,
	)
	accessClient := access.NewClient(
		inputs.HTTPClient,
		inputs.DiscoveryClient,
		tokenClient,
		inputs.PeerOrigin,
	)

	inboxSharesHandler := inboxshares.NewHandler(
		inputs.IncomingShareRepo,
		accessClient,
		currentUser,
		log,
	)

	outgoingHandler := outgoingshares.NewHandler(
		inputs.OutgoingShareRepo,
		inputs.DiscoveryClient,
		inputs.HTTPClient,
		inputs.Signer,
		inputs.LocalIdentity.ProviderDomain,
		currentUser,
		log,
	)
	outgoingHandler.SetPeerOrigin(inputs.PeerOrigin)
	outgoingHandler.SetCodeFlow(inputs.CodeFlow)
	if len(c.AllowedPaths) > 0 {
		outgoingHandler.SetAllowedPaths(c.AllowedPaths)
	}

	inboxInvitesHandler := inboxinvites.NewHandler(
		inputs.IncomingInviteRepo,
		inputs.HTTPClient,
		inputs.DiscoveryClient,
		inputs.Signer,
		inputs.LocalIdentity.ProviderDomain,
		currentUser,
		log,
	)
	inboxInvitesHandler.SetPeerOrigin(inputs.PeerOrigin)

	outgoingInvitesHandler := outgoinginvites.NewHandler(
		inputs.OutgoingInviteRepo,
		inputs.LocalIdentity.ProviderDomain,
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
	r.Get(RouteHealthz, api.HealthHandler)

	if loginMiddleware != nil {
		r.With(loginMiddleware).Post(RouteAuthLogin, authHandler.Login)
	} else {
		r.Post(RouteAuthLogin, authHandler.Login)
	}
	r.Post(RouteAuthLogout, authHandler.Logout)
	r.Get(RouteAuthMe, authHandler.GetCurrentUser)

	r.Get(RouteInboxShares, inboxSharesHandler.HandleList)
	r.Get(RouteInboxShareDetail, inboxSharesHandler.HandleGetDetail)
	r.Post(RouteInboxShareAccept, inboxSharesHandler.HandleAccept)
	r.Post(RouteInboxShareDecline, inboxSharesHandler.HandleDecline)
	r.Post(RouteInboxShareVerifyAccess, inboxSharesHandler.HandleVerifyAccess)
	r.Get(RouteInboxInvites, inboxInvitesHandler.HandleList)
	r.Post(RouteInboxInviteImport, inboxInvitesHandler.HandleImport)
	r.Post(RouteInboxInviteAccept, inboxInvitesHandler.HandleAccept)
	r.Post(RouteInboxInviteDecline, inboxInvitesHandler.HandleDecline)

	r.Post(RouteSharesOutgoing, outgoingHandler.HandleCreate)
	r.Post(RouteInvitesOutgoing, outgoingInvitesHandler.HandleCreateOutgoing)

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
	default:
		return nil
	}
}

func (s *Service) Handler() http.Handler {
	return httpwrap.ClearRawPath(s.router)
}

func (s *Service) Prefix() string {
	return "api"
}

func (s *Service) Close() error {
	return nil
}
