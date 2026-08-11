// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package ocm

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/outgoing/accepted"
	notificationsincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/notifications/incoming"
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
		return nil, fmt.Errorf("services: decode service config: %w", err)
	}

	if len(unused) > 0 {
		log.Warn("unused config keys", "service", "ocm", "unused_keys", unused)
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
		return nil, fmt.Errorf("services: validate token exchange config: %w", err)
	}

	sharesHandler := sharesincoming.NewHandler(
		inputs.IncomingShareRepo,
		inputs.PartyRepo,
		inputs.PolicyEngine,
		inputs.IncomingInviteRepo,
		inputs.OutgoingInviteRepo,
		inputs.MustInviteEnforced,
		inputs.LocalIdentity.ProviderDomainCompare,
		inputs.LocalIdentity.Scheme,
		inputs.PeerMappingResolver,
	)
	invitesHandler := accepted.NewHandler(
		inputs.OutgoingInviteRepo,
		inputs.PartyRepo,
		inputs.PolicyEngine,
		inputs.LocalIdentity.ProviderDomain,
		inputs.LocalIdentity.Scheme,
	)
	tokenHandler := tokenincoming.NewHandler(
		inputs.OutgoingShareRepo,
		inputs.TokenStore,
		&c.TokenExchange,
		inputs.CodeFlow,
		inputs.LocalIdentity.Origin,
	)
	notificationsHandler := notificationsincoming.NewHandler(
		inputs.OutgoingShareRepo,
		inputs.IncomingShareRepo,
		inputs.LocalIdentity.Scheme,
		log,
	)

	peerResolver := peer.NewResolver()
	r := chi.NewRouter()

	routeOpts := service.RouteOpts{
		ExternalBasePath:  inputs.LocalIdentity.ExternalBasePath,
		TokenExchangePath: c.TokenExchange.Path,
	}
	if err := mountProtocolRoutes(r, routeOpts, inputs, routeHandlers{
		shares:         sharesHandler.CreateShare,
		inviteAccepted: invitesHandler.HandleInviteAccepted,
		token:          tokenHandler.HandleToken,
		notifications:  notificationsHandler.HandleNotification,
	}, peerResolver); err != nil {
		return nil, err
	}

	mountJWKSRoute(r, inputs)

	return &Service{
		router: r,
		conf:   &c,
		log:    log,
	}, nil
}

func validateInputs(in Inputs) error {
	switch {
	case in.SignatureMiddleware == nil:
		return errors.New("ocm: SignatureMiddleware is required")
	case in.PartyRepo == nil:
		return errors.New("ocm: PartyRepo is required")
	default:
		return nil
	}
}

// Handler returns the service HTTP handler; implements service.Service.
func (s *Service) Handler() http.Handler {
	return httpwrap.ClearRawPath(s.router)
}

// Prefix returns the service URL prefix; implements service.Service.
func (s *Service) Prefix() string {
	return string(service.BuildOCM)
}

// Close performs no cleanup for this service; implements service.Service.
func (s *Service) Close() error {
	return nil
}
