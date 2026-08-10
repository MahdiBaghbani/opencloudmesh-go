// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity/sessiongate"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/realip"
	tlspkg "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/tls"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
)

// trackingService is a test service that records when Close() is called.
type trackingService struct {
	name       string
	prefix     string
	closeOrder *[]string
}

func (t *trackingService) Handler() http.Handler { return http.NotFoundHandler() }
func (t *trackingService) Prefix() string        { return t.prefix }
func (t *trackingService) Close() error {
	*t.closeOrder = append(*t.closeOrder, t.name)

	return nil
}

func testServerDeps(t *testing.T, cfg *config.Config, logger *slog.Logger) ServerDeps {
	t.Helper()

	partyRepo := identity.NewMemoryPartyRepo()
	sessionRepo := identity.NewMemorySessionRepo()
	realIP := realip.NewTrustedProxies(nil)

	return ServerDeps{
		RealIP: realIP,
		AuthGate: func(requireAuth func(string) bool) func(http.Handler) http.Handler {
			return sessiongate.NewAuthGate(sessiongate.AuthGateConfig{
				RequireAuth: requireAuth,
				Log:         logger,
				SessionRepo: sessionRepo,
				PartyRepo:   partyRepo,
				BasePath:    cfg.ExternalBasePath,
			})
		},
	}
}

func TestNew_FailsWithMissingServerDeps(t *testing.T) {
	t.Parallel()

	cfg := config.DevConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	t.Run("empty deps", func(t *testing.T) {
		t.Parallel()

		_, err := New(cfg, logger, nil, ServerDeps{})
		if err == nil {
			t.Fatal("expected error for missing server deps")
		}

		if !errors.Is(err, ErrMissingRealIP) {
			t.Errorf("expected ErrMissingRealIP, got: %v", err)
		}
	})

	t.Run("missing auth gate", func(t *testing.T) {
		t.Parallel()

		sd := ServerDeps{RealIP: realip.NewTrustedProxies(nil)}

		_, err := New(cfg, logger, nil, sd)
		if err == nil {
			t.Fatal("expected error for missing auth gate")
		}

		if !errors.Is(err, ErrMissingAuthGate) {
			t.Errorf("expected ErrMissingAuthGate, got: %v", err)
		}
	})
}

func TestNew_SetsReadHeaderTimeout(t *testing.T) {
	t.Parallel()

	cfg := config.DevConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	srv, err := New(cfg, logger, nil, testServerDeps(t, cfg, logger))
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	if got := srv.httpServer.ReadHeaderTimeout; got != config.DefaultServerReadHeaderTimeout {
		t.Errorf("main server ReadHeaderTimeout = %v, want %v", got, config.DefaultServerReadHeaderTimeout)
	}

	cfg.TLS.HTTPPort = getFreePort(t)
	cfg.TLS.ACME.Domain = "localhost"
	acmeMgr := tlspkg.NewACMEManager(&cfg.TLS.ACME, logger, nil)

	challengeServer, listener, err := srv.startChallengeServer(acmeMgr, "127.0.0.1")
	if err != nil {
		t.Fatalf("startChallengeServer failed: %v", err)
	}

	tshttp.MustClose(t, listener)

	if got := challengeServer.ReadHeaderTimeout; got != config.DefaultChallengeReadHeaderTimeout {
		t.Errorf("challenge server ReadHeaderTimeout = %v, want %v", got, config.DefaultChallengeReadHeaderTimeout)
	}
}

func TestNew_SucceedsWithServerDeps(t *testing.T) {
	t.Parallel()

	cfg := config.DevConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	srv, err := New(cfg, logger, nil, testServerDeps(t, cfg, logger))
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}

	if srv == nil {
		t.Fatal("expected non-nil server")
	}
}

func TestShutdown_ClosesServicesInReverseOrder(t *testing.T) {
	t.Parallel()

	cfg := config.DevConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	var closeOrder []string

	svc1 := &trackingService{name: "svc1", prefix: "svc1", closeOrder: &closeOrder}
	svc2 := &trackingService{name: "svc2", prefix: "svc2", closeOrder: &closeOrder}
	svc3 := &trackingService{name: "svc3", prefix: "svc3", closeOrder: &closeOrder}

	srv, err := New(cfg, logger, map[string]service.Service{
		"ocmaux": svc1,
		"api":    svc2,
		"ui":     svc3,
	}, testServerDeps(t, cfg, logger))
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	// Shutdown should close services in reverse mount order
	ctx := context.Background()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown failed: %v", err)
	}

	// Services mounted in order: svc1, svc2, svc3
	// Should close in reverse: svc3, svc2, svc1
	expected := []string{"svc3", "svc2", "svc1"}
	if len(closeOrder) != len(expected) {
		t.Fatalf("expected %d services closed, got %d: %v", len(expected), len(closeOrder), closeOrder)
	}

	for i, name := range expected {
		if closeOrder[i] != name {
			t.Errorf("close order[%d] = %q, want %q", i, closeOrder[i], name)
		}
	}
}

func TestHTTPSRedirectHandler_CanonicalDomain(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://[::1]:9080/x?q=1", nil)
	req.Host = "[::1]:9080"
	rec := httptest.NewRecorder()

	newHTTPSRedirectHandler("example.com", 9443).ServeHTTP(rec, req)

	if rec.Code != http.StatusPermanentRedirect {
		t.Fatalf("status = %d, want 308", rec.Code)
	}

	if got := rec.Header().Get("Location"); got != "https://example.com:9443/x?q=1" {
		t.Fatalf("Location = %q, want %q", got, "https://example.com:9443/x?q=1")
	}
}

func TestHTTPSRedirect_IgnoresSpoofedHost(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://127.0.0.1/evil/path", nil)
	req.Host = "evil.example"
	rec := httptest.NewRecorder()

	newHTTPSRedirectHandler("localhost", 9443).ServeHTTP(rec, req)

	if rec.Code != http.StatusPermanentRedirect {
		t.Fatalf("status = %d, want 308", rec.Code)
	}

	got := rec.Header().Get("Location")

	want := "https://localhost:9443/evil/path"
	if got != want {
		t.Fatalf("Location = %q, want %q", got, want)
	}
}

// Verify trackingService implements service.Service.
var _ service.Service = (*trackingService)(nil)
