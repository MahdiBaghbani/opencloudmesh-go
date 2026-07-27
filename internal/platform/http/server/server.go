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

	if err := validateACMEConfig(s.cfg); err != nil {
		return err
	}

	acmeMgr := tlspkg.NewACMEManager(&s.cfg.TLS.ACME, s.logger, s.RootCAPool)

	challengeServer, challengeListener, err := s.startChallengeServer(acmeMgr, host)
	if err != nil {
		return err
	}

	challengeErrCh := make(chan error, 1)
	go func() {
		challengeErrCh <- challengeServer.Serve(challengeListener)
	}()

	if initErr := acmeMgr.Init(context.Background()); initErr != nil {
		s.closeChallengeServer()
		return fmt.Errorf("ACME initialization failed: %w", initErr)
	}

	s.httpServer.Addr = net.JoinHostPort(host, strconv.Itoa(s.cfg.TLS.HTTPSPort))
	s.httpServer.TLSConfig = acmeMgr.GetTLSConfig()

	httpsListener, err := net.Listen("tcp", s.httpServer.Addr) //nolint:noctx // listener is bound once at server startup; no caller-supplied shutdown context is available here
	if err != nil {
		s.closeChallengeServer()
		return fmt.Errorf("https listener bind failed on %s: %w", s.httpServer.Addr, err)
	}

	httpsErrCh := make(chan error, 1)
	go func() {
		httpsErrCh <- s.httpServer.ServeTLS(httpsListener, "", "")
	}()

	s.logger.Info("starting ACME server",
		"http_addr", challengeServer.Addr,
		"https_addr", s.httpServer.Addr,
		"domain", s.cfg.TLS.ACME.Domain,
	)

	return s.runACMEServers(httpsErrCh, challengeErrCh)
}

func validateACMEConfig(cfg *config.Config) error {
	if cfg.TLS.HTTPPort == 0 {
		return errors.New("tls.http_port must be set for ACME mode")
	}

	if cfg.TLS.HTTPSPort == 0 {
		return errors.New("tls.https_port must be set for ACME mode")
	}

	if cfg.PublicOrigin == "" {
		return nil
	}

	originURL, parseErr := url.Parse(cfg.PublicOrigin)
	if parseErr != nil || originURL.Host == "" {
		return nil
	}

	_, portStr, splitErr := net.SplitHostPort(originURL.Host)
	if splitErr != nil || portStr == "" {
		return nil
	}

	originPort, convErr := strconv.Atoi(portStr)
	if convErr != nil {
		return nil
	}

	if originPort != cfg.TLS.HTTPSPort {
		return fmt.Errorf("public_origin port %d does not match tls.https_port %d", originPort, cfg.TLS.HTTPSPort)
	}

	return nil
}

func (s *Server) startChallengeServer(acmeMgr *tlspkg.ACMEManager, host string) (*http.Server, net.Listener, error) {
	challengeMux := http.NewServeMux()
	challengeMux.Handle("/.well-known/acme-challenge/", acmeMgr.ChallengeHandler())
	challengeMux.Handle("/", newHTTPSRedirectHandler(s.cfg.TLS.HTTPSPort))

	httpAddr := net.JoinHostPort(host, strconv.Itoa(s.cfg.TLS.HTTPPort))
	challengeServer := &http.Server{
		Addr:         httpAddr,
		Handler:      challengeMux,
		ReadTimeout:  config.DefaultChallengeReadTimeout,
		WriteTimeout: config.DefaultChallengeWriteTimeout,
		IdleTimeout:  config.DefaultChallengeIdleTimeout,
	}

	s.challengeServer = challengeServer

	challengeListener, err := net.Listen("tcp", httpAddr) //nolint:noctx // listener is bound once at server startup; no caller-supplied shutdown context is available here
	if err != nil {
		return nil, nil, fmt.Errorf("challenge listener bind failed on %s: %w", httpAddr, err)
	}

	return challengeServer, challengeListener, nil
}

func (s *Server) closeChallengeServer() {
	if s.challengeServer == nil {
		return
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), config.DefaultServerShutdownTimeout)
	defer cancel()

	if shutdownErr := s.challengeServer.Shutdown(shutdownCtx); shutdownErr != nil && !errors.Is(shutdownErr, http.ErrServerClosed) {
		//nolint:errcheck // best-effort cleanup; error is not actionable
		s.challengeServer.Close()
	}
}

func (s *Server) runACMEServers(httpsErrCh, challengeErrCh chan error) error {
	select {
	case httpsErr := <-httpsErrCh:
		s.closeChallengeServer()
		return httpsErr
	case challengeErr := <-challengeErrCh:
		if errors.Is(challengeErr, http.ErrServerClosed) {
			return <-httpsErrCh
		}

		shutdownCtx, cancel := context.WithTimeout(context.Background(), config.DefaultServerShutdownTimeout)
		defer cancel()

		//nolint:errcheck // best-effort cleanup; error is not actionable
		s.httpServer.Shutdown(shutdownCtx)

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

		//nolint:gosec // target is same-host HTTPS upgrade built from r.Host and r.URL, not a user-supplied URL
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
