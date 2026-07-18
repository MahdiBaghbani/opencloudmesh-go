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
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
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

	if inputs.CodeFlow != nil {
		c.TokenExchange.Enabled = inputs.CodeFlow.Evaluate().TokenExchangeCapable
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
		inputs.CodeFlow,
		inputs.PeerOrigin,
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
		inputs.PeerContract,
		inputs.LocalIdentity.Origin,
		log,
	)

	peerResolver := peer.NewResolver()
	r := chi.NewRouter()

	r.With(inputs.SignatureMiddleware.VerifyOCMRequestRequireSignatureAndPeer(peerResolver.ResolveSharesRequest)).
		Post(RouteShares, sharesHandler.CreateShare)
	// Notifications stay signature-only: no body-declared peer resolver.
	r.With(inputs.SignatureMiddleware.VerifyOCMRequestRequireSignature(nil)).
		Post(RouteNotifications, notifHandler.HandleNotification)
	r.With(inputs.SignatureMiddleware.VerifyOCMRequestRequireSignatureAndPeer(peerResolver.ResolveInviteAcceptedRequest)).
		Post(RouteInviteAccepted, invitesHandler.HandleInviteAccepted)
	r.With(inputs.SignatureMiddleware.VerifyOCMRequestRequireSignatureAndPeer(peerResolver.ResolveTokenRequest)).
		Post(c.TokenExchange.RoutePath(), tokenHandler.HandleToken)
	// Request-share is a signed, peer-bound placeholder: accept handling is
	// not implemented, so it always answers with a typed 501.
	r.With(inputs.SignatureMiddleware.VerifyOCMRequestRequireSignatureAndPeer(peerResolver.ResolveRequestShareRequest)).
		Post(RouteRequestShare, requestShareNotSupportedHandler)

	return &Service{
		router: r,
		conf:   &c,
		log:    log,
	}, nil
}

func validateInputs(in Inputs) error {
	if in.SignatureMiddleware == nil {
		return errors.New("ocm: SignatureMiddleware is required")
	}
	return nil
}

// requestShareNotSupportedHandler answers the signed request-share placeholder
// route. Accept handling is not implemented, so every request gets a typed 501.
func requestShareNotSupportedHandler(w http.ResponseWriter, r *http.Request) {
	spec.WriteRequestShareNotSupported(w)
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
