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
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/services"
)

var (
	ErrMissingSharedDeps   = errors.New("shared deps not initialized: call services.SetDeps() before server.New()")
	ErrACMENotImplemented  = errors.New("tls.mode=acme is not implemented; use static or selfsigned")
)

// Server wraps the HTTP server and its dependencies.
type Server struct {
	cfg              *config.Config
	httpServer       *http.Server
	logger           *slog.Logger
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

	// mountedServices tracks services for lifecycle management (Close on shutdown).
	// Stored in mount order; closed in reverse order during shutdown.
	mountedServices []services.Service
}

// New creates a new Server with the given configuration.
// All dependencies are obtained from services.GetDeps() (SharedDeps).
// Returns an error if SharedDeps is not initialized.
// wellknownSvc is the Reva-aligned wellknown service for discovery endpoints.
// ocmSvc is the Reva-aligned OCM protocol service for /ocm/* endpoints.
// ocmauxSvc is the Reva-aligned ocm-aux service for WAYF helper endpoints.
// apiserviceSvc is the Reva-aligned API service for /api/* endpoints.
// uiserviceSvc is the Reva-aligned UI service for /ui/* endpoints.
// webdavserviceSvc is the Reva-aligned WebDAV service for /webdav/* endpoints.
func New(cfg *config.Config, logger *slog.Logger, wellknownSvc services.Service, ocmSvc services.Service, ocmauxSvc services.Service, apiserviceSvc services.Service, uiserviceSvc services.Service, webdavserviceSvc services.Service) (*Server, error) {
	// Fail fast: SharedDeps must be initialized before server creation
	deps := services.GetDeps()
	if deps == nil {
		return nil, ErrMissingSharedDeps
	}

	// NOTE: All handlers are now constructed by their respective services (Reva-aligned).
	// Services access dependencies via services.GetDeps().

	// Create signer for outgoing requests (from SharedDeps)
	var signer *crypto.RFC9421Signer
	if deps.KeyManager != nil {
		signer = crypto.NewRFC9421Signer(deps.KeyManager)
	}

	// Create trusted proxy handler for X-Forwarded-* header processing
	trustedProxies := NewTrustedProxies(cfg.Server.TrustedProxies)

	// Create signature verification middleware
	peerDiscoveryAdapter := NewPeerDiscoveryAdapter(deps.DiscoveryClient)
	signatureMiddleware := crypto.NewSignatureMiddleware(&cfg.Signature, peerDiscoveryAdapter, logger)

	s := &Server{
		cfg:                 cfg,
		logger:              logger,
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

// Shutdown gracefully shuts down the server and all mounted services.
func (s *Server) Shutdown(ctx context.Context) error {
	s.logger.Info("shutting down server")

	// Shutdown HTTP server first
	httpErr := s.httpServer.Shutdown(ctx)

	// Close services in reverse mount order (last mounted = first closed)
	for i := len(s.mountedServices) - 1; i >= 0; i-- {
		svc := s.mountedServices[i]
		prefix := svc.Prefix()
		if prefix == "" {
			prefix = "(root)"
		}
		if err := svc.Close(); err != nil {
			s.logger.Warn("service close error",
				"service", prefix,
				"error", err,
			)
			// Continue closing other services (best-effort)
		} else {
			s.logger.Debug("service closed", "service", prefix)
		}
	}

	return httpErr
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

