// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity/sessiongate"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/realip"
)

type realipProbeService struct {
	realIP *realip.TrustedProxies
}

func (p *realipProbeService) Handler() http.Handler {
	r := chi.NewRouter()
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		//nolint:errcheck // probe response is fixed JSON on a test-only route
		json.NewEncoder(w).Encode(map[string]any{
			"clientIp":  p.realIP.GetClientIPString(r),
			"usesHttps": realip.RequestUsesHTTPS(r),
		})
	})

	return r
}

func (p *realipProbeService) Prefix() string { return "api" }

func (p *realipProbeService) Close() error { return nil }

func TestSetupRoutes_TerminatedForwardingOnMountedRoute(t *testing.T) {
	t.Parallel()

	cfg := config.DevConfig()
	cfg.TLS.Mode = config.TLSModeTerminated
	cfg.Server.TrustedProxies = []string{"127.0.0.0/8"}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	tp, err := realip.NewTrustedProxiesStrict(cfg.Server.TrustedProxies)
	if err != nil {
		t.Fatalf("NewTrustedProxiesStrict: %v", err)
	}

	tp = tp.EnableStrictForwarded()

	deps := testServerDeps(t, cfg, logger)
	deps.RealIP = tp

	probe := &realipProbeService{realIP: tp}

	srv, err := New(cfg, logger, map[string]service.Service{
		string(service.BuildAPI): probe,
	}, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://backend.local/api/healthz", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Host = "backend.local:8080"
	req.Header.Set("X-Forwarded-For", "203.0.113.10")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "cloud.example.com")

	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}

	var payload struct {
		ClientIP  string `json:"clientIp"`
		UsesHTTPS bool   `json:"usesHttps"`
	}

	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode probe response: %v", err)
	}

	if payload.ClientIP != "203.0.113.10" {
		t.Errorf("client_ip = %q, want 203.0.113.10", payload.ClientIP)
	}

	if !payload.UsesHTTPS {
		t.Fatal("expected uses_https true through production setupRoutes middleware chain")
	}
}

func TestSetupRoutes_PlainHTTPAbsoluteFormHTTPSSpoofNonSecure(t *testing.T) {
	t.Parallel()

	cfg := config.DevConfig()
	cfg.TLS.Mode = config.TLSModeTerminated
	cfg.Server.TrustedProxies = []string{"127.0.0.0/8"}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	tp, err := realip.NewTrustedProxiesStrict(cfg.Server.TrustedProxies)
	if err != nil {
		t.Fatalf("NewTrustedProxiesStrict: %v", err)
	}

	deps := testServerDeps(t, cfg, logger)
	deps.RealIP = tp.EnableStrictForwarded()

	probe := &realipProbeService{realIP: deps.RealIP}

	srv, err := New(cfg, logger, map[string]service.Service{
		string(service.BuildAPI): probe,
	}, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodGet,
		"http://cloud.example.com/api/healthz",
		nil,
	)
	req.URL.Scheme = "https"
	req.RemoteAddr = "203.0.113.99:12345"

	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}

	var payload struct {
		ClientIP  string `json:"clientIp"`
		UsesHTTPS bool   `json:"usesHttps"`
	}

	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode probe response: %v", err)
	}

	if payload.ClientIP != "203.0.113.99" {
		t.Errorf("client_ip = %q, want 203.0.113.99", payload.ClientIP)
	}

	if payload.UsesHTTPS {
		t.Fatal("expected uses_https false for absolute-form https URL without trusted forwarding")
	}
}

func TestSetupRoutes_AuthLoginSecureCookie_TerminatedForwardedHTTPS(t *testing.T) {
	t.Parallel()

	authSvc := newAuthRealipWiringService(t)
	authSvc.seedUser(t, "alice", "secret123")

	cfg := config.DevConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	srv, _ := newTerminatedRealIPServer(t, authSvc, authWiringServerDeps(t, cfg, logger, authSvc))

	body := `{"username":"alice","password":"secret123"}`
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://backend.local/api/auth/login", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "127.0.0.1:12345"
	req.Host = "backend.local:8080"
	req.Header.Set("X-Forwarded-For", "203.0.113.10")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "cloud.example.com")

	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}

	sessionCookie := findWiringSessionCookie(t, rec.Result().Cookies())
	if !sessionCookie.Secure {
		t.Fatal("expected Secure login cookie through production setupRoutes middleware chain")
	}
}

func TestSetupRoutes_AuthLogoutSecureCookie_TerminatedForwardedHTTPS(t *testing.T) {
	t.Parallel()

	authSvc := newAuthRealipWiringService(t)
	authSvc.seedUser(t, "alice", "secret123")

	ctx := context.Background()

	user, err := authSvc.repo.GetByUsername(ctx, "alice")
	if err != nil {
		t.Fatalf("GetByUsername: %v", err)
	}

	session, err := authSvc.sessions.Create(ctx, user.ID, api.SessionTTL)
	if err != nil {
		t.Fatalf("Create session: %v", err)
	}

	cfg := config.DevConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	srv, _ := newTerminatedRealIPServer(t, authSvc, authWiringServerDeps(t, cfg, logger, authSvc))

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://backend.local/api/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer "+session.Token)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Host = "backend.local:8080"
	req.Header.Set("X-Forwarded-For", "203.0.113.10")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "cloud.example.com")

	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}

	sessionCookie := findWiringSessionCookie(t, rec.Result().Cookies())
	if !sessionCookie.Secure {
		t.Fatal("expected Secure logout cookie through production setupRoutes middleware chain")
	}
}

func TestSetupRoutes_AuthLoginNonSecureCookie_PlainHTTP(t *testing.T) {
	t.Parallel()

	authSvc := newAuthRealipWiringService(t)
	authSvc.seedUser(t, "alice", "secret123")

	cfg := config.DevConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	srv, _ := newTerminatedRealIPServer(t, authSvc, authWiringServerDeps(t, cfg, logger, authSvc))

	body := `{"username":"alice","password":"secret123"}`
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://backend.local/api/auth/login", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "203.0.113.99:12345"

	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}

	sessionCookie := findWiringSessionCookie(t, rec.Result().Cookies())
	if sessionCookie.Secure {
		t.Fatal("expected non-Secure login cookie for plain HTTP without validated forwarding")
	}
}

func TestSetupRoutes_TerminatedMalformedForwardedRequestRejected(t *testing.T) {
	t.Parallel()

	probe := &realipProbeService{realIP: nil}
	srv, tp := newTerminatedRealIPServer(t, probe)
	probe.realIP = tp

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://backend.local/api/healthz", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Host = "backend.local:8080"
	req.Header.Set("X-Forwarded-For", "not-an-ip")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "cloud.example.com")

	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", rec.Code, rec.Body.String())
	}
}

var _ service.Service = (*realipProbeService)(nil)

type authRealipWiringService struct {
	handler  *api.AuthHandler
	repo     identity.PartyRepo
	sessions identity.SessionRepo
	auth     *identity.UserAuth
}

func newAuthRealipWiringService(t *testing.T) *authRealipWiringService {
	t.Helper()

	repo := identity.NewMemoryPartyRepo()
	sessions := identity.NewMemorySessionRepo()
	userAuth := identity.NewUserAuthFast()

	return &authRealipWiringService{
		handler:  api.NewAuthHandler(repo, sessions, userAuth),
		repo:     repo,
		sessions: sessions,
		auth:     userAuth,
	}
}

func (s *authRealipWiringService) Handler() http.Handler {
	r := chi.NewRouter()
	r.Post("/auth/login", s.handler.Login)
	r.Post("/auth/logout", s.handler.Logout)

	return r
}

func (s *authRealipWiringService) Prefix() string { return "api" }

func (s *authRealipWiringService) Close() error { return nil }

func (s *authRealipWiringService) seedUser(t *testing.T, username, password string) {
	t.Helper()

	ctx := context.Background()

	hash, err := s.auth.HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	user := &identity.User{
		Username:     username,
		PasswordHash: hash,
		DisplayName:  username,
		Role:         "user",
	}
	if err := s.repo.Create(ctx, user); err != nil {
		t.Fatalf("Create user: %v", err)
	}
}

func newTerminatedRealIPServer(t *testing.T, svc service.Service, depsOverride ...ServerDeps) (*Server, *realip.TrustedProxies) {
	t.Helper()

	cfg := config.DevConfig()
	cfg.TLS.Mode = config.TLSModeTerminated
	cfg.Server.TrustedProxies = []string{"127.0.0.0/8"}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	tp, err := realip.NewTrustedProxiesStrict(cfg.Server.TrustedProxies)
	if err != nil {
		t.Fatalf("NewTrustedProxiesStrict: %v", err)
	}

	var deps ServerDeps
	if len(depsOverride) > 0 {
		deps = depsOverride[0]
	} else {
		deps = testServerDeps(t, cfg, logger)
	}

	deps.RealIP = tp.EnableStrictForwarded()

	srv, err := New(cfg, logger, map[string]service.Service{
		string(service.BuildAPI): svc,
	}, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	return srv, deps.RealIP
}

func authWiringServerDeps(t *testing.T, cfg *config.Config, logger *slog.Logger, authSvc *authRealipWiringService) ServerDeps {
	t.Helper()

	realIP := realip.NewTrustedProxies(nil)

	return ServerDeps{
		RealIP: realIP,
		AuthGate: func(requireAuth func(string) bool) func(http.Handler) http.Handler {
			return sessiongate.NewAuthGate(sessiongate.AuthGateConfig{
				RequireAuth: requireAuth,
				Log:         logger,
				SessionRepo: authSvc.sessions,
				PartyRepo:   authSvc.repo,
				BasePath:    cfg.ExternalBasePath,
			})
		},
	}
}

func findWiringSessionCookie(t *testing.T, cookies []*http.Cookie) *http.Cookie {
	t.Helper()

	for _, c := range cookies {
		if c.Name == "session" {
			return c
		}
	}

	t.Fatal("expected session cookie to be set")

	return nil
}
