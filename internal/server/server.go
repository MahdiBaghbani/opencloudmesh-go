// Package server provides HTTP server wiring and lifecycle management.
package server

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/api"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/federation"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/ocm/invites"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/ocm/notifications"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/ocm/shares"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/ui"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/webdav"
)

// Deps holds all server dependencies.
type Deps struct {
	PartyRepo            identity.PartyRepo
	SessionRepo          identity.SessionRepo
	UserAuth             *identity.UserAuth
	KeyManager           *crypto.KeyManager
	FederationMgr        *federation.FederationManager
	DiscoveryClient      *discovery.Client
	PolicyEngine         *federation.PolicyEngine
	IncomingShareRepo    shares.IncomingShareRepo
	OutgoingShareRepo    shares.OutgoingShareRepo
	OutgoingInviteRepo   invites.OutgoingInviteRepo
	IncomingInviteRepo   invites.IncomingInviteRepo
}

// Server wraps the HTTP server and its dependencies.
type Server struct {
	cfg              *config.Config
	httpServer       *http.Server
	logger           *slog.Logger
	deps             *Deps
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
}

// New creates a new Server with the given configuration.
func New(cfg *config.Config, logger *slog.Logger, deps *Deps) (*Server, error) {
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
		nil, // HTTP client - will be configured later
		signer,
		cfg,
		logger,
	)

	// Create WebDAV handler
	webdavHandler := webdav.NewHandler(deps.OutgoingShareRepo, logger)

	// Create notifications handler
	notificationsHandler := notifications.NewHandler(deps.OutgoingShareRepo, logger)

	// Create inbox actions handler (notification client will be nil for now)
	inboxActionsHandler := shares.NewInboxActionsHandler(deps.IncomingShareRepo, nil, logger)

	// Extract provider FQDN from external origin
	providerFQDN := extractProviderFQDN(cfg.ExternalOrigin)

	// Create invites handler
	invitesHandler := invites.NewHandler(deps.OutgoingInviteRepo, providerFQDN, logger)

	// Create invites inbox handler (with nil HTTP client for now)
	invitesInboxHandler := invites.NewInboxHandler(
		deps.IncomingInviteRepo,
		deps.DiscoveryClient,
		nil, // HTTP client - will be configured later
		signer,
		"", // Our user ID
		providerFQDN,
		logger,
	)

	s := &Server{
		cfg:              cfg,
		logger:           logger,
		deps:             deps,
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
