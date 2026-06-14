// Package ocm provides the OCM protocol service for OpenCloudMesh.
package ocm

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	invitesincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/incoming"
	notifincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/notifications/incoming"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peer"
	sharesincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/incoming"
	tokenincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token/incoming"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	svccfg "github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service/cfg"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service/httpwrap"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
)

// Config holds OCM service configuration.
type Config struct {
	TokenExchange tokenincoming.TokenExchangeSettings `mapstructure:"token_exchange"`
}

// ApplyDefaults sets default values for unset fields.
func (c *Config) ApplyDefaults() {
	c.TokenExchange.ApplyDefaults()
}

// Service is the OCM protocol service.
type Service struct {
	router chi.Router
	conf   *Config
	log    *slog.Logger
}

// New creates a new OCM protocol service from narrow injected inputs.
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
		log.Warn("unused config keys", "service", "ocm", "unused_keys", unused)
	}

	if inputs.OpenCloudMeshPolicy != nil {
		c.TokenExchange.Enabled = inputs.OpenCloudMeshPolicy.Evaluate().TokenExchangeCapable
	}
	var rawTE map[string]any
	if te, ok := m["token_exchange"].(map[string]any); ok {
		rawTE = te
	}
	if _, set := rawTE["path"]; !set {
		c.TokenExchange.Path = inputs.TokenExchangePath
		if c.TokenExchange.Path == "" {
			c.TokenExchange.Path = "token"
		}
	}

	if err := c.TokenExchange.Validate(); err != nil {
		return nil, err
	}

	sharesHandler := sharesincoming.NewHandler(
		inputs.IncomingShareRepo,
		inputs.PartyRepo,
		inputs.PolicyEngine,
		inputs.DiscoveryClient,
		inputs.OpenCloudMeshPolicy,
		inputs.RuntimePolicy,
		inputs.PeerContract,
		inputs.LocalIdentity.ProviderDomainCompare,
		inputs.LocalIdentity.Scheme,
		log,
	)
	notifHandler := notifincoming.NewHandler(inputs.OutgoingShareRepo, inputs.LocalIdentity.Origin, log)
	invitesHandler := invitesincoming.NewHandler(
		inputs.OutgoingInviteRepo,
		inputs.PartyRepo,
		inputs.PolicyEngine,
		inputs.LocalIdentity.ProviderDomain,
		inputs.LocalIdentity.Scheme,
		log,
	)
	tokenHandler := tokenincoming.NewHandler(
		inputs.OutgoingShareRepo,
		inputs.TokenStore,
		&c.TokenExchange,
		inputs.LocalIdentity.Origin,
		log,
	)

	peerResolver := peer.NewResolver()
	r := chi.NewRouter()

	if inputs.SignatureMiddleware != nil {
		r.With(inputs.SignatureMiddleware.VerifyOCMRequest(peerResolver.ResolveSharesRequest)).
			Post(RouteShares, sharesHandler.CreateShare)
		r.With(inputs.SignatureMiddleware.VerifyOCMRequest(peerResolver.ResolveNotificationsRequest)).
			Post(RouteNotifications, notifHandler.HandleNotification)
		r.With(inputs.SignatureMiddleware.VerifyOCMRequest(peerResolver.ResolveInviteAcceptedRequest)).
			Post(RouteInviteAccepted, invitesHandler.HandleInviteAccepted)
		r.With(inputs.SignatureMiddleware.VerifyOCMRequest(peerResolver.ResolveTokenRequest)).
			Post(c.TokenExchange.RoutePath(), tokenHandler.HandleToken)
	} else {
		r.Post(RouteShares, sharesHandler.CreateShare)
		r.Post(RouteNotifications, notifHandler.HandleNotification)
		r.Post(RouteInviteAccepted, invitesHandler.HandleInviteAccepted)
		r.Post(c.TokenExchange.RoutePath(), tokenHandler.HandleToken)
	}

	return &Service{
		router: r,
		conf:   &c,
		log:    log,
	}, nil
}

func validateInputs(in Inputs) error {
	if in.RuntimePolicy == nil {
		return errors.New("ocm: RuntimePolicy is required")
	}
	return nil
}

func (s *Service) Handler() http.Handler {
	return httpwrap.ClearRawPath(s.router)
}

func (s *Service) Prefix() string {
	return "ocm"
}

func (s *Service) Close() error {
	return nil
}
