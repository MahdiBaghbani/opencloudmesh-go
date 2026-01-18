// Package server provides HTTP server wiring and lifecycle management.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/federation"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/httpclient"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/ocm/invites"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/ocm/shares"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/ocm/token"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/services"
)

var (
	ErrMissingDep          = errors.New("missing required dependency")
	ErrACMENotImplemented  = errors.New("tls.mode=acme is not implemented; use static or selfsigned")
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

	// Optional: peer profiles for outbound signing decisions
	ProfileRegistry *federation.ProfileRegistry

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
	wellknownSvc     services.Service // Reva-aligned wellknown service for discovery
	ocmSvc           services.Service // Reva-aligned OCM protocol service
	ocmauxSvc        services.Service // Reva-aligned ocm-aux service for WAYF helpers
	apiserviceSvc    services.Service // Reva-aligned API service for /api/* endpoints
	uiserviceSvc     services.Service // Reva-aligned UI service for /ui/* endpoints
	webdavserviceSvc services.Service // Reva-aligned WebDAV service for /webdav/* endpoints
	signer           *crypto.RFC9421Signer
	peerResolver     *crypto.PeerResolver
	signatureMiddleware *crypto.SignatureMiddleware
}

// New creates a new Server with the given configuration.
// Returns an error if required dependencies are missing.
// wellknownSvc is the Reva-aligned wellknown service for discovery endpoints.
// ocmSvc is the Reva-aligned OCM protocol service for /ocm/* endpoints.
// ocmauxSvc is the Reva-aligned ocm-aux service for WAYF helper endpoints.
// apiserviceSvc is the Reva-aligned API service for /api/* endpoints.
// uiserviceSvc is the Reva-aligned UI service for /ui/* endpoints.
// webdavserviceSvc is the Reva-aligned WebDAV service for /webdav/* endpoints.
func New(cfg *config.Config, logger *slog.Logger, deps *Deps, wellknownSvc services.Service, ocmSvc services.Service, ocmauxSvc services.Service, apiserviceSvc services.Service, uiserviceSvc services.Service, webdavserviceSvc services.Service) (*Server, error) {
	// Fail fast: validate required dependencies
	if err := validateDeps(deps); err != nil {
		return nil, err
	}

	// Initialize default in-memory repos for optional dependencies
	initializeDefaultRepos(deps)

	// NOTE: UI handler is now constructed by uiservice (Reva-aligned).
	// NOTE: Auth handler is now constructed by apiservice (Reva-aligned).
	// NOTE: Discovery is now handled by the wellknown service (Reva-aligned).
	// NOTE: WebDAV handler is now constructed by webdavservice (Reva-aligned).
	// Public keys are computed at wellknown service construction time via SharedDeps.

	// Create signer for outgoing requests
	var signer *crypto.RFC9421Signer
	if deps.KeyManager != nil {
		signer = crypto.NewRFC9421Signer(deps.KeyManager)
	}

	// NOTE: OCM auxiliary endpoints (/ocm-aux/*) are now handled by the ocmaux service.
	// NOTE: API endpoints (/api/*) are now handled by the apiservice.
	// NOTE: WebDAV endpoints (/webdav/*) are now handled by the webdavservice.

	// NOTE: OCM protocol handlers (shares, notifications, invites/invite-accepted, token)
	// are now constructed by the OCM service (Reva-aligned pattern).

	// Create trusted proxy handler for X-Forwarded-* header processing
	trustedProxies := NewTrustedProxies(cfg.Server.TrustedProxies)

	// Create signature verification middleware
	peerDiscoveryAdapter := NewPeerDiscoveryAdapter(deps.DiscoveryClient)
	signatureMiddleware := crypto.NewSignatureMiddleware(&cfg.Signature, peerDiscoveryAdapter, logger)

	s := &Server{
		cfg:                 cfg,
		logger:              logger,
		deps:                deps,
		trustedProxies:      trustedProxies,
		wellknownSvc:        wellknownSvc,
		ocmSvc:              ocmSvc,
		ocmauxSvc:           ocmauxSvc,
		apiserviceSvc:       apiserviceSvc,
		uiserviceSvc:        uiserviceSvc,
		webdavserviceSvc:    webdavserviceSvc,
		signer:              signer,
		peerResolver:        crypto.NewPeerResolver(),
		signatureMiddleware: signatureMiddleware,
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

	switch s.cfg.TLS.Mode {
	case "off":
		return s.httpServer.ListenAndServe()

	case "acme":
		// ACME is not implemented - fail fast with a clear error
		return ErrACMENotImplemented

	case "static", "selfsigned":
		// Get TLS config from TLS manager
		tlsManager := NewTLSManager(&s.cfg.TLS, s.logger)
		hostname := extractHostname(s.cfg.ExternalOrigin)
		tlsConfig, err := tlsManager.GetTLSConfig(hostname)
		if err != nil {
			return fmt.Errorf("failed to configure TLS: %w", err)
		}
		if tlsConfig == nil {
			return fmt.Errorf("TLS config is nil for mode %s", s.cfg.TLS.Mode)
		}

		// Configure server with TLS
		s.httpServer.TLSConfig = tlsConfig
		s.logger.Info("starting server with TLS", "mode", s.cfg.TLS.Mode)

		// For static and selfsigned modes, certs are in TLSConfig.Certificates
		// ListenAndServeTLS with empty strings uses TLSConfig.Certificates
		return s.httpServer.ListenAndServeTLS("", "")

	default:
		return fmt.Errorf("%w: %s", ErrInvalidTLSMode, s.cfg.TLS.Mode)
	}
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

// extractHostname extracts just the hostname from an external origin URL.
// For TLS certificate generation, we need the hostname without port.
func extractHostname(externalOrigin string) string {
	fqdn := extractProviderFQDN(externalOrigin)
	// Remove port if present
	for i := len(fqdn) - 1; i >= 0; i-- {
		if fqdn[i] == ':' {
			return fqdn[:i]
		}
		if fqdn[i] == ']' {
			// IPv6 address like [::1]:8080
			break
		}
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

// initializeDefaultRepos initializes in-memory repos for optional dependencies
// that are nil. This ensures handlers always have valid repos to work with.
func initializeDefaultRepos(deps *Deps) {
	if deps.IncomingShareRepo == nil {
		deps.IncomingShareRepo = shares.NewMemoryIncomingShareRepo()
	}
	if deps.OutgoingShareRepo == nil {
		deps.OutgoingShareRepo = shares.NewMemoryOutgoingShareRepo()
	}
	if deps.OutgoingInviteRepo == nil {
		deps.OutgoingInviteRepo = invites.NewMemoryOutgoingInviteRepo()
	}
	if deps.IncomingInviteRepo == nil {
		deps.IncomingInviteRepo = invites.NewMemoryIncomingInviteRepo()
	}
	if deps.TokenStore == nil {
		deps.TokenStore = token.NewMemoryTokenStore()
	}
}
