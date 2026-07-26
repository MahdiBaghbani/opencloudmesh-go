package wiring

import (
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/realip"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/server"
)

func TestBuildServerDeps_FailsWithoutSharedDeps(t *testing.T) {
	cfg := config.DevConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	_, err := BuildServerDeps(cfg, logger, nil)
	if err == nil {
		t.Fatal("expected error when shared deps are nil")
	}

	if !errors.Is(err, server.ErrMissingServerDeps) {
		t.Fatalf("expected ErrMissingServerDeps, got: %v", err)
	}
}

func TestBuildServerDeps_FailsWithoutRealIP(t *testing.T) {
	cfg := config.DevConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	d := &Deps{
		PartyRepo:   identity.NewMemoryPartyRepo(),
		SessionRepo: identity.NewMemorySessionRepo(),
	}

	_, err := BuildServerDeps(cfg, logger, d)
	if err == nil {
		t.Fatal("expected error when RealIP is nil")
	}

	if !errors.Is(err, server.ErrMissingRealIP) {
		t.Fatalf("expected ErrMissingRealIP, got: %v", err)
	}
}

func TestBuildServerDeps_FailsWithoutAuthRepos(t *testing.T) {
	cfg := config.DevConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	d := &Deps{
		RealIP: realip.NewTrustedProxies(nil),
	}

	_, err := BuildServerDeps(cfg, logger, d)
	if err == nil {
		t.Fatal("expected error when auth repos are nil")
	}

	if !errors.Is(err, server.ErrMissingAuthRepos) {
		t.Fatalf("expected ErrMissingAuthRepos, got: %v", err)
	}
}

func TestBuildServerDeps_SucceedsWithSharedDeps(t *testing.T) {
	cfg := config.DevConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	d := &Deps{
		RealIP:      realip.NewTrustedProxies(nil),
		PartyRepo:   identity.NewMemoryPartyRepo(),
		SessionRepo: identity.NewMemorySessionRepo(),
	}

	sd, err := BuildServerDeps(cfg, logger, d)
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}

	if sd.AuthGate == nil {
		t.Fatal("expected injected auth gate")
	}

	if sd.RealIP == nil {
		t.Fatal("expected injected RealIP")
	}
}

func TestBuildServerDeps_AuthGateDoesNotPanicOnProtectedRoute(t *testing.T) {
	cfg := config.DevConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	d := &Deps{
		RealIP:      realip.NewTrustedProxies(nil),
		PartyRepo:   identity.NewMemoryPartyRepo(),
		SessionRepo: identity.NewMemorySessionRepo(),
	}

	sd, err := BuildServerDeps(cfg, logger, d)
	if err != nil {
		t.Fatalf("BuildServerDeps: %v", err)
	}

	requireAuth := func(path string) bool { return path == "/protected" }
	handler := sd.AuthGate(requireAuth)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without session, got %d", rec.Code)
	}
}
