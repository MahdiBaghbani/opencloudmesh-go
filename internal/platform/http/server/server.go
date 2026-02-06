// Package server provides HTTP server wiring and lifecycle management.
package server

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/deps"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/instanceid"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"

	tlspkg "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/tls"
)

var ErrMissingSharedDeps = errors.New("shared deps not initialized: call deps.SetDeps() before server.New()")

// Server wraps the HTTP server and its dependencies.
type Server struct {
	cfg        *config.Config
	httpServer *http.Server
	logger     *slog.Logger
	services   map[string]service.Service // keyed by service name (wellknown, ocm, ...)
	signer     *crypto.RFC9421Signer

	// challengeServer is the HTTP listener for ACME HTTP-01 challenges and
	// HTTPS redirects. Nil except in ACME mode.
	challengeServer *http.Server

	// RootCAPool is the merged root CA pool for outbound TLS and ACME directory. Set by main.go before Start().
	RootCAPool *x509.CertPool

	// mountedServices tracks services for lifecycle management (Close on shutdown).
	// Stored in mount order; closed in reverse order during shutdown.
	mountedServices []service.Service
}

// New creates a new Server with the given configuration.
// Services are passed as a name->service map; nil entries are safe (skipped at mount time).
// All dependencies are obtained from deps.GetDeps() (SharedDeps).
// Returns an error if SharedDeps is not initialized.
func New(cfg *config.Config, logger *slog.Logger, services map[string]service.Service) (*Server, error) {
	logger = logutil.NoopIfNil(logger)

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
		cfg:      cfg,
		logger:   logger,
		services: services,
		signer:   signer,
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

// SetRootCAPool sets the root CA pool for ACME directory communication (Phase 3).
// Call before Start().
func (s *Server) SetRootCAPool(pool *x509.CertPool) {
	s.RootCAPool = pool
}

// Start starts the HTTP server. It blocks until the server is shut down.
func (s *Server) Start() error {
	s.logger.Info("starting server",
		"addr", s.cfg.ListenAddr,
		"public_origin", s.cfg.PublicOrigin,
		"external_base_path", s.cfg.ExternalBasePath,
		"tls_mode", s.cfg.TLS.Mode,
	)

	switch s.cfg.TLS.Mode {
	case "off":
		return s.httpServer.ListenAndServe()

	case "acme":
		return s.startACME()

	case "static", "selfsigned":
		// Get TLS config from TLS manager
		tlsManager := tlspkg.NewTLSManager(&s.cfg.TLS, s.logger)
		hostname, err := instanceid.Hostname(s.cfg.PublicOrigin)
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

// startACME runs the server in ACME mode with two listeners:
// an HTTP listener for HTTP-01 challenges and HTTPS redirects,
// and an HTTPS listener for the application router.
func (s *Server) startACME() error {
	// Parse bind host from ListenAddr (port part is ignored; we use HTTPPort/HTTPSPort).
	host, _, err := net.SplitHostPort(s.cfg.ListenAddr)
	if err != nil {
		// ListenAddr might be a bare host or IP without a port.
		host = s.cfg.ListenAddr
	}

	if s.cfg.TLS.HTTPPort == 0 {
		return errors.New("tls.http_port must be set for ACME mode")
	}
	if s.cfg.TLS.HTTPSPort == 0 {
		return errors.New("tls.https_port must be set for ACME mode")
	}

	// When PublicOrigin includes an explicit port, it must match HTTPSPort.
	if s.cfg.PublicOrigin != "" {
		if originURL, parseErr := url.Parse(s.cfg.PublicOrigin); parseErr == nil && originURL.Host != "" {
			if _, portStr, splitErr := net.SplitHostPort(originURL.Host); splitErr == nil && portStr != "" {
				if originPort, convErr := strconv.Atoi(portStr); convErr == nil && originPort != s.cfg.TLS.HTTPSPort {
					return fmt.Errorf("public_origin port %d does not match tls.https_port %d", originPort, s.cfg.TLS.HTTPSPort)
				}
			}
		}
	}

	acmeMgr := tlspkg.NewACMEManager(&s.cfg.TLS.ACME, s.logger, s.RootCAPool)

	// HTTP router: challenges on their well-known path, redirect everything else.
	challengeMux := http.NewServeMux()
	challengeMux.Handle("/.well-known/acme-challenge/", acmeMgr.ChallengeHandler())
	challengeMux.Handle("/", newHTTPSRedirectHandler(s.cfg.TLS.HTTPSPort))

	httpAddr := net.JoinHostPort(host, strconv.Itoa(s.cfg.TLS.HTTPPort))
	s.challengeServer = &http.Server{
		Addr:         httpAddr,
		Handler:      challengeMux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	challengeListener, err := net.Listen("tcp", httpAddr)
	if err != nil {
		return fmt.Errorf("challenge listener bind failed on %s: %w", httpAddr, err)
	}

	closeChallengeServer := func() {
		if s.challengeServer == nil {
			return
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if shutdownErr := s.challengeServer.Shutdown(shutdownCtx); shutdownErr != nil && !errors.Is(shutdownErr, http.ErrServerClosed) {
			_ = s.challengeServer.Close()
		}
	}

	// Start the challenge server in a goroutine.
	challengeErrCh := make(chan error, 1)
	go func() {
		challengeErrCh <- s.challengeServer.Serve(challengeListener)
	}()

	// Init loads existing certs (fast path) or contacts the ACME server.
	if initErr := acmeMgr.Init(context.Background()); initErr != nil {
		closeChallengeServer()
		return fmt.Errorf("ACME initialization failed: %w", initErr)
	}

	// Configure the main HTTPS server with the ACME-managed certificate.
	s.httpServer.Addr = net.JoinHostPort(host, strconv.Itoa(s.cfg.TLS.HTTPSPort))
	s.httpServer.TLSConfig = acmeMgr.GetTLSConfig()

	httpsListener, err := net.Listen("tcp", s.httpServer.Addr)
	if err != nil {
		closeChallengeServer()
		return fmt.Errorf("https listener bind failed on %s: %w", s.httpServer.Addr, err)
	}

	httpsErrCh := make(chan error, 1)
	go func() {
		httpsErrCh <- s.httpServer.ServeTLS(httpsListener, "", "")
	}()

	s.logger.Info("starting ACME server",
		"http_addr", httpAddr,
		"https_addr", s.httpServer.Addr,
		"domain", s.cfg.TLS.ACME.Domain,
	)

	select {
	case httpsErr := <-httpsErrCh:
		closeChallengeServer()
		return httpsErr
	case challengeErr := <-challengeErrCh:
		if errors.Is(challengeErr, http.ErrServerClosed) {
			return <-httpsErrCh
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.httpServer.Shutdown(shutdownCtx)
		return fmt.Errorf("challenge server exited unexpectedly: %w", challengeErr)
	}
}

// newHTTPSRedirectHandler returns a handler that issues HTTP 308 Permanent
// Redirect to the HTTPS equivalent of the request URL.
func newHTTPSRedirectHandler(httpsPort int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hostOnly := r.Host
		if h, _, err := net.SplitHostPort(hostOnly); err == nil {
			hostOnly = h
		}
		if strings.Contains(hostOnly, ":") && !(strings.HasPrefix(hostOnly, "[") && strings.HasSuffix(hostOnly, "]")) {
			hostOnly = "[" + hostOnly + "]"
		}

		var target string
		if httpsPort == 443 {
			target = "https://" + hostOnly + r.URL.RequestURI()
		} else {
			target = fmt.Sprintf("https://%s:%d%s", hostOnly, httpsPort, r.URL.RequestURI())
		}

		http.Redirect(w, r, target, http.StatusPermanentRedirect)
	})
}

// Shutdown gracefully shuts down the server and all mounted services.
func (s *Server) Shutdown(ctx context.Context) error {
	s.logger.Info("shutting down server")

	// In ACME mode, stop accepting challenges before tearing down HTTPS.
	var challengeErr error
	if s.challengeServer != nil {
		challengeErr = s.challengeServer.Shutdown(ctx)
	}

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

	return errors.Join(challengeErr, httpErr)
}
