// Package server provides HTTP server wiring and lifecycle management.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/deps"
)

var (
	ErrMissingSharedDeps   = errors.New("shared deps not initialized: call deps.SetDeps() before server.New()")
	ErrACMENotImplemented  = errors.New("tls.mode=acme is not implemented; use static or selfsigned")
)

// Server wraps the HTTP server and its dependencies.
type Server struct {
	cfg              *config.Config
	httpServer       *http.Server
	logger           *slog.Logger
	wellknownSvc     service.Service // Reva-aligned wellknown service for discovery
	ocmSvc           service.Service // Reva-aligned OCM protocol service
	ocmauxSvc        service.Service // Reva-aligned ocm-aux service for WAYF helpers
	apiSvc    service.Service // Reva-aligned API service for /api/* endpoints
	uiSvc     service.Service // Reva-aligned UI service for /ui/* endpoints
	webdavSvc service.Service // Reva-aligned WebDAV service for /webdav/* endpoints
	signer           *crypto.RFC9421Signer

	// mountedServices tracks services for lifecycle management (Close on shutdown).
	// Stored in mount order; closed in reverse order during shutdown.
	mountedServices []service.Service
}

// New creates a new Server with the given configuration.
// All dependencies are obtained from deps.GetDeps() (SharedDeps).
// Returns an error if SharedDeps is not initialized.
// wellknownSvc is the Reva-aligned wellknown service for discovery endpoints.
// ocmSvc is the Reva-aligned OCM protocol service for /ocm/* endpoints.
// ocmauxSvc is the Reva-aligned ocm-aux service for WAYF helper endpoints.
// apiSvc is the Reva-aligned API service for /api/* endpoints.
// uiSvc is the Reva-aligned UI service for /ui/* endpoints.
// webdavSvc is the Reva-aligned WebDAV service for /webdav/* endpoints.
func New(cfg *config.Config, logger *slog.Logger, wellknownSvc service.Service, ocmSvc service.Service, ocmauxSvc service.Service, apiSvc service.Service, uiSvc service.Service, webdavSvc service.Service) (*Server, error) {
	// Fail fast: SharedDeps must be initialized before server creation
	d := deps.GetDeps()
	if d == nil {
		return nil, ErrMissingSharedDeps
	}

	// NOTE: All handlers are now constructed by their respective services (Reva-aligned).
	// Services access dependencies via deps.GetDeps().

	// Create signer for outgoing requests (from SharedDeps)
	var signer *crypto.RFC9421Signer
	if d.KeyManager != nil {
		signer = crypto.NewRFC9421Signer(d.KeyManager)
	}

	// NOTE: SignatureMiddleware is now owned by services (OCM service applies it internally).
	// It is constructed in main.go and available via SharedDeps.SignatureMiddleware.
	// NOTE: RealIP extractor is owned by SharedDeps (deps.RealIP), not by Server.
	// All client IP extraction for logging and rate limiting uses deps.GetDeps().RealIP.

	s := &Server{
		cfg:              cfg,
		logger:           logger,
		wellknownSvc:     wellknownSvc,
		ocmSvc:           ocmSvc,
		ocmauxSvc:        ocmauxSvc,
		apiSvc:    apiSvc,
		uiSvc:     uiSvc,
		webdavSvc: webdavSvc,
		signer:           signer,
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

