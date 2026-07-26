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

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/instanceid"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"

	tlspkg "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/tls"
)

var (
	ErrMissingServerDeps = errors.New("shared deps not provided")
	ErrMissingRealIP     = errors.New("real IP extractor not provided")
	ErrMissingAuthGate   = errors.New("auth gate not provided")
	ErrMissingAuthRepos  = errors.New("auth repos not provided")
)

// Server wraps the HTTP server and its dependencies.
type Server struct {
	cfg        *config.Config
	httpServer *http.Server
	logger     *slog.Logger
	services   map[string]service.Service
	deps       ServerDeps

	challengeServer *http.Server
	RootCAPool      *x509.CertPool
	mountedServices []service.Service
}

// New creates a new Server with injected dependencies and the given services map.
func New(
	cfg *config.Config,
	logger *slog.Logger,
	services map[string]service.Service,
	sd ServerDeps,
) (*Server, error) {
	logger = logutil.NoopIfNil(logger)

	if sd.RealIP == nil {
		return nil, ErrMissingRealIP
	}

	if sd.AuthGate == nil {
		return nil, ErrMissingAuthGate
	}

	s := &Server{
		cfg:      cfg,
		logger:   logger,
		services: services,
		deps:     sd,
	}

	router := s.setupRoutes()

	s.httpServer = &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      router,
		ReadTimeout:  config.DefaultServerReadTimeout,
		WriteTimeout: config.DefaultServerWriteTimeout,
		IdleTimeout:  config.DefaultServerIdleTimeout,
	}

	return s, nil
}

func (s *Server) SetRootCAPool(pool *x509.CertPool) {
	s.RootCAPool = pool
}

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

		s.httpServer.TLSConfig = tlsConfig
		s.logger.Info("starting server with TLS", "mode", s.cfg.TLS.Mode)

		return s.httpServer.ListenAndServeTLS("", "")

	default:
		return fmt.Errorf("%w: %s", tlspkg.ErrInvalidTLSMode, s.cfg.TLS.Mode)
	}
}

func (s *Server) startACME() error {
	host, _, err := net.SplitHostPort(s.cfg.ListenAddr)
	if err != nil {
		host = s.cfg.ListenAddr
	}

	if s.cfg.TLS.HTTPPort == 0 {
		return errors.New("tls.http_port must be set for ACME mode")
	}

	if s.cfg.TLS.HTTPSPort == 0 {
		return errors.New("tls.https_port must be set for ACME mode")
	}

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

	challengeMux := http.NewServeMux()
	challengeMux.Handle("/.well-known/acme-challenge/", acmeMgr.ChallengeHandler())
	challengeMux.Handle("/", newHTTPSRedirectHandler(s.cfg.TLS.HTTPSPort))

	httpAddr := net.JoinHostPort(host, strconv.Itoa(s.cfg.TLS.HTTPPort))
	s.challengeServer = &http.Server{
		Addr:         httpAddr,
		Handler:      challengeMux,
		ReadTimeout:  config.DefaultChallengeReadTimeout,
		WriteTimeout: config.DefaultChallengeWriteTimeout,
		IdleTimeout:  config.DefaultChallengeIdleTimeout,
	}

	challengeListener, err := net.Listen("tcp", httpAddr)
	if err != nil {
		return fmt.Errorf("challenge listener bind failed on %s: %w", httpAddr, err)
	}

	closeChallengeServer := func() {
		if s.challengeServer == nil {
			return
		}

		shutdownCtx, cancel := context.WithTimeout(context.Background(), config.DefaultServerShutdownTimeout)
		defer cancel()

		if shutdownErr := s.challengeServer.Shutdown(shutdownCtx); shutdownErr != nil && !errors.Is(shutdownErr, http.ErrServerClosed) {
			_ = s.challengeServer.Close()
		}
	}

	challengeErrCh := make(chan error, 1)
	go func() {
		challengeErrCh <- s.challengeServer.Serve(challengeListener)
	}()

	if initErr := acmeMgr.Init(context.Background()); initErr != nil {
		closeChallengeServer()
		return fmt.Errorf("ACME initialization failed: %w", initErr)
	}

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

		shutdownCtx, cancel := context.WithTimeout(context.Background(), config.DefaultServerShutdownTimeout)
		defer cancel()

		_ = s.httpServer.Shutdown(shutdownCtx)

		return fmt.Errorf("challenge server exited unexpectedly: %w", challengeErr)
	}
}

func newHTTPSRedirectHandler(httpsPort int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hostOnly := r.Host
		if h, _, err := net.SplitHostPort(hostOnly); err == nil {
			hostOnly = h
		}

		if strings.Contains(hostOnly, ":") && (!strings.HasPrefix(hostOnly, "[") || !strings.HasSuffix(hostOnly, "]")) {
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

func (s *Server) Shutdown(ctx context.Context) error {
	s.logger.Info("shutting down server")

	var challengeErr error
	if s.challengeServer != nil {
		challengeErr = s.challengeServer.Shutdown(ctx)
	}

	httpErr := s.httpServer.Shutdown(ctx)

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
		} else {
			s.logger.Debug("service closed", "service", prefix)
		}
	}

	return errors.Join(challengeErr, httpErr)
}
