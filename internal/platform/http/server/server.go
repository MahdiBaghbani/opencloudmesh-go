// Package server provides HTTP server wiring and lifecycle management.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/deps"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/instanceid"

	tlspkg "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/tls"
)

var ErrMissingSharedDeps = errors.New("shared deps not initialized: call deps.SetDeps() before server.New()")

// Server wraps the HTTP server and its dependencies.
type Server struct {
	cfg          *config.Config
	httpServer   *http.Server
	logger       *slog.Logger
	wellknownSvc service.Service // Reva-aligned wellknown service for discovery
	ocmSvc       service.Service // Reva-aligned OCM protocol service
	ocmauxSvc    service.Service // Reva-aligned ocm-aux service for WAYF helpers
	apiSvc       service.Service // Reva-aligned API service for /api/* endpoints
	uiSvc        service.Service // Reva-aligned UI service for /ui/* endpoints
	webdavSvc    service.Service // Reva-aligned WebDAV service for /webdav/* endpoints
	signer       *crypto.RFC9421Signer

	// mountedServices tracks services for lifecycle management (Close on shutdown).
	// Stored in mount order; closed in reverse order during shutdown.
	mountedServices []service.Service
}

// New creates a new Server with the given configuration.
// All dependencies are obtained from deps.GetDeps() (SharedDeps).
// Returns an error if SharedDeps is not initialized.
func New(cfg *config.Config, logger *slog.Logger, wellknownSvc service.Service, ocmSvc service.Service, ocmauxSvc service.Service, apiSvc service.Service, uiSvc service.Service, webdavSvc service.Service) (*Server, error) {
	// Fail fast: SharedDeps must be initialized before server creation
	d := deps.GetDeps()
	if d == nil {
		return nil, ErrMissingSharedDeps
	}

	// Create signer for outgoing requests (from SharedDeps)
	var signer *crypto.RFC9421Signer
	if d.KeyManager != nil {
		signer = crypto.NewRFC9421Signer(d.KeyManager)
	}

	s := &Server{
		cfg:          cfg,
		logger:       logger,
		wellknownSvc: wellknownSvc,
		ocmSvc:       ocmSvc,
		ocmauxSvc:    ocmauxSvc,
		apiSvc:       apiSvc,
		uiSvc:        uiSvc,
		webdavSvc:    webdavSvc,
		signer:       signer,
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
		return tlspkg.ErrACMENotImplemented

	case "static", "selfsigned":
		// Get TLS config from TLS manager
		tlsManager := tlspkg.NewTLSManager(&s.cfg.TLS, s.logger)
		hostname, err := instanceid.Hostname(s.cfg.ExternalOrigin)
		if err != nil {
			return fmt.Errorf("failed to derive TLS hostname: %w", err)
		}
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
		return fmt.Errorf("%w: %s", tlspkg.ErrInvalidTLSMode, s.cfg.TLS.Mode)
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
