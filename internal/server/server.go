// Package server provides HTTP server wiring and lifecycle management.
package server

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/config"
)

// Server wraps the HTTP server and its dependencies.
type Server struct {
	cfg        *config.Config
	httpServer *http.Server
	logger     *slog.Logger
}

// New creates a new Server with the given configuration.
func New(cfg *config.Config, logger *slog.Logger) *Server {
	s := &Server{
		cfg:    cfg,
		logger: logger,
	}

	router := s.setupRoutes()

	s.httpServer = &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return s
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
