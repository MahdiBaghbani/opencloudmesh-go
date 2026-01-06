// Package server provides HTTP server wiring and lifecycle management.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/api"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/federation"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/httpclient"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/ocm/invites"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/ocm/notifications"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/ocm/shares"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/ocm/token"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/ui"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/webdav"
)

var (
	ErrMissingDep = errors.New("missing required dependency")
)

// Deps holds all server dependencies.
type Deps struct {
	// Required: identity and auth
	PartyRepo   identity.PartyRepo
	SessionRepo identity.SessionRepo
	UserAuth    *identity.UserAuth

	// Required: outbound HTTP client for server-to-server communication
	HTTPClient *httpclient.ContextClient

	// Optional: signature key manager (nil if signature mode is off)
	KeyManager *crypto.KeyManager

	// Optional: federation (nil if federation is not configured)
	FederationMgr   *federation.FederationManager
	DiscoveryClient *discovery.Client
	PolicyEngine    *federation.PolicyEngine

	// Optional: persistence repos (nil uses in-memory or disabled features)
	IncomingShareRepo  shares.IncomingShareRepo
	OutgoingShareRepo  shares.OutgoingShareRepo
	OutgoingInviteRepo invites.OutgoingInviteRepo
	IncomingInviteRepo invites.IncomingInviteRepo
	TokenStore         token.TokenStore
}

// Server wraps the HTTP server and its dependencies.
type Server struct {
	cfg              *config.Config
	httpServer       *http.Server
	logger           *slog.Logger
	deps             *Deps
	trustedProxies   *TrustedProxies
	authHandler      *api.AuthHandler
	uiHandler        *ui.Handler
	discoveryHandler *discovery.Handler
	signer           *crypto.RFC9421Signer
	peerResolver     *crypto.PeerResolver
	auxHandler       *federation.AuxHandler
	sharesHandler         *shares.Handler
	inboxHandler          *shares.InboxHandler
	inboxActionsHandler   *shares.InboxActionsHandler
	outgoingHandler       *shares.OutgoingHandler
	webdavHandler         *webdav.Handler
	notificationsHandler  *notifications.Handler
	invitesHandler        *invites.Handler
	invitesInboxHandler   *invites.InboxHandler
	tokenHandler          *token.Handler
}

// New creates a new Server with the given configuration.
// Returns an error if required dependencies are missing.
func New(cfg *config.Config, logger *slog.Logger, deps *Deps) (*Server, error) {
	// Fail fast: validate required dependencies
	if err := validateDeps(deps); err != nil {
		return nil, err
	}

	// Create UI handler
	uiHandler, err := ui.NewHandler(cfg.ExternalBasePath)
	if err != nil {
		return nil, err
	}

	// Create auth handler
	authHandler := api.NewAuthHandler(deps.PartyRepo, deps.SessionRepo, deps.UserAuth)

	// Create discovery handler
	discoveryHandler := discovery.NewHandler(cfg)

	// Set up public keys in discovery if signature mode is not off
	if cfg.Signature.Mode != "off" && deps.KeyManager != nil {
		discoveryHandler.SetPublicKeys([]discovery.PublicKey{
			{
				KeyID:        deps.KeyManager.GetKeyID(),
				PublicKeyPem: deps.KeyManager.GetPublicKeyPEM(),
				Algorithm:    "ed25519",
			},
		})
	}

	// Create signer for outgoing requests
	var signer *crypto.RFC9421Signer
	if deps.KeyManager != nil {
		signer = crypto.NewRFC9421Signer(deps.KeyManager)
	}

	// Create auxiliary handler for federation endpoints
	auxHandler := federation.NewAuxHandler(deps.FederationMgr, deps.DiscoveryClient)

	// Create shares handler
	sharesHandler := shares.NewHandler(deps.IncomingShareRepo, deps.PolicyEngine, logger, true)

	// Create inbox handler
	inboxHandler := shares.NewInboxHandler(deps.IncomingShareRepo)

	// Create outgoing share handler
	outgoingHandler := shares.NewOutgoingHandler(
		deps.OutgoingShareRepo,
		deps.DiscoveryClient,
		deps.HTTPClient,
		signer,
		cfg,
		logger,
	)

	// Create WebDAV handler
	webdavHandler := webdav.NewHandler(deps.OutgoingShareRepo, logger)

	// Create notifications handler
	notificationsHandler := notifications.NewHandler(deps.OutgoingShareRepo, logger)

	// Create notification client for outbound notifications
	notificationClient := notifications.NewClient(deps.HTTPClient, deps.DiscoveryClient, signer)

	// Create inbox actions handler
	inboxActionsHandler := shares.NewInboxActionsHandler(deps.IncomingShareRepo, notificationClient, logger)

	// Extract provider FQDN from external origin
	providerFQDN := extractProviderFQDN(cfg.ExternalOrigin)

	// Create invites handler
	invitesHandler := invites.NewHandler(deps.OutgoingInviteRepo, providerFQDN, logger)

	// Create invites inbox handler
	invitesInboxHandler := invites.NewInboxHandler(
		deps.IncomingInviteRepo,
		deps.DiscoveryClient,
		deps.HTTPClient,
		signer,
		"", // Our user ID - will be set from session context
		providerFQDN,
		logger,
	)

	// Create token handler
	tokenHandler := token.NewHandler(deps.OutgoingShareRepo, deps.TokenStore, logger)

	// Create trusted proxy handler for X-Forwarded-* header processing
	trustedProxies := NewTrustedProxies(cfg.Server.TrustedProxies)

	s := &Server{
		cfg:              cfg,
		logger:           logger,
		deps:             deps,
		trustedProxies:   trustedProxies,
		authHandler:      authHandler,
		uiHandler:        uiHandler,
		discoveryHandler: discoveryHandler,
		signer:           signer,
		peerResolver:     crypto.NewPeerResolver(),
		auxHandler:       auxHandler,
		sharesHandler:         sharesHandler,
		inboxHandler:          inboxHandler,
		inboxActionsHandler:   inboxActionsHandler,
		outgoingHandler:       outgoingHandler,
		webdavHandler:         webdavHandler,
		notificationsHandler:  notificationsHandler,
		invitesHandler:        invitesHandler,
		invitesInboxHandler:   invitesInboxHandler,
		tokenHandler:          tokenHandler,
	}

	router := s.setupRoutes()

	s.httpServer = &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return s, nil
}

// Start starts the HTTP server. It blocks until the server is shut down.
func (s *Server) Start() error {
	s.logger.Info("starting server",
		"addr", s.cfg.ListenAddr,
		"external_origin", s.cfg.ExternalOrigin,
		"external_base_path", s.cfg.ExternalBasePath,
		"tls_mode", s.cfg.TLS.Mode,
	)

	// For Phase 0, we start with HTTP only. TLS is added in Phase 0d.
	if s.cfg.TLS.Mode == "off" {
		return s.httpServer.ListenAndServe()
	}

	// Placeholder for TLS modes - will be implemented in Phase 0d
	s.logger.Warn("TLS mode not fully implemented yet, falling back to HTTP",
		"tls_mode", s.cfg.TLS.Mode)
	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown(ctx context.Context) error {
	s.logger.Info("shutting down server")
	return s.httpServer.Shutdown(ctx)
}

// extractProviderFQDN extracts the host:port from an external origin URL.
func extractProviderFQDN(externalOrigin string) string {
	// Remove scheme
	fqdn := externalOrigin
	if idx := len("https://"); len(fqdn) > idx && fqdn[:idx] == "https://" {
		fqdn = fqdn[idx:]
	} else if idx := len("http://"); len(fqdn) > idx && fqdn[:idx] == "http://" {
		fqdn = fqdn[idx:]
	}
	// Remove trailing slash
	if len(fqdn) > 0 && fqdn[len(fqdn)-1] == '/' {
		fqdn = fqdn[:len(fqdn)-1]
	}
	return fqdn
}

// validateDeps checks that all required dependencies are provided.
func validateDeps(deps *Deps) error {
	if deps == nil {
		return errors.New("deps is nil")
	}

	// Required: identity and auth
	if deps.PartyRepo == nil {
		return fmt.Errorf("%w: PartyRepo", ErrMissingDep)
	}
	if deps.SessionRepo == nil {
		return fmt.Errorf("%w: SessionRepo", ErrMissingDep)
	}
	if deps.UserAuth == nil {
		return fmt.Errorf("%w: UserAuth", ErrMissingDep)
	}

	// Required: outbound HTTP client
	if deps.HTTPClient == nil {
		return fmt.Errorf("%w: HTTPClient", ErrMissingDep)
	}

	// Optional deps are allowed to be nil
	return nil
}
