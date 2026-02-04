package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	tlspkg "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/tls"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/deps"
)

// trackingService is a test service that records when Close() is called.
type trackingService struct {
	name       string
	prefix     string
	closeOrder *[]string
}

func (t *trackingService) Handler() http.Handler { return http.NotFoundHandler() }
func (t *trackingService) Prefix() string        { return t.prefix }
func (t *trackingService) Unprotected() []string  { return nil }
func (t *trackingService) Close() error {
	*t.closeOrder = append(*t.closeOrder, t.name)
	return nil
}

// setupTestSharedDeps sets up SharedDeps for testing and returns a cleanup function.
func setupTestSharedDeps(t *testing.T) func() {
	t.Helper()
	deps.ResetDeps()
	deps.SetDeps(&deps.Deps{
		PartyRepo:   identity.NewMemoryPartyRepo(),
		SessionRepo: identity.NewMemorySessionRepo(),
		UserAuth:    identity.NewUserAuth(1),
		HTTPClient:  httpclient.NewContextClient(httpclient.New(nil, nil)),
	})
	return func() {
		deps.ResetDeps()
	}
}

func TestNew_FailsWithNilSharedDeps(t *testing.T) {
	cfg := config.DevConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	// Ensure SharedDeps is nil
	deps.ResetDeps()
	defer deps.ResetDeps()

	_, err := New(cfg, logger, nil)
	if err == nil {
		t.Fatal("expected error for nil SharedDeps")
	}
	if !errors.Is(err, ErrMissingSharedDeps) {
		t.Errorf("expected ErrMissingSharedDeps, got: %v", err)
	}
}

func TestNew_SucceedsWithSharedDeps(t *testing.T) {
	cfg := config.DevConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	cleanup := setupTestSharedDeps(t)
	defer cleanup()

	srv, err := New(cfg, logger, nil) // nil service map acceptable for tests
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if srv == nil {
		t.Fatal("expected non-nil server")
	}
}

func TestShutdown_ClosesServicesInReverseOrder(t *testing.T) {
	cfg := config.DevConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	cleanup := setupTestSharedDeps(t)
	defer cleanup()

	// Track close order
	var closeOrder []string

	// Create tracking services
	svc1 := &trackingService{name: "svc1", prefix: "svc1", closeOrder: &closeOrder}
	svc2 := &trackingService{name: "svc2", prefix: "svc2", closeOrder: &closeOrder}
	svc3 := &trackingService{name: "svc3", prefix: "svc3", closeOrder: &closeOrder}

	// Create server with services in map (mount order: ocmaux, api, ui)
	srv, err := New(cfg, logger, map[string]service.Service{
		"ocmaux": svc1,
		"api":    svc2,
		"ui":     svc3,
	})
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

// Verify trackingService implements service.Service
var _ service.Service = (*trackingService)(nil)

func TestACME_FailFast(t *testing.T) {
	// ACME mode should fail fast when Server.Start() is called
	cfg := config.DevConfig()
	cfg.TLS.Mode = "acme"
	cfg.ListenAddr = ":0" // Dynamic port

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	cleanup := setupTestSharedDeps(t)
	defer cleanup()

	srv, err := New(cfg, logger, nil)
	if err != nil {
		t.Fatalf("server creation failed: %v", err)
	}

	// Start should fail fast with ACME error
	err = srv.Start()
	if !errors.Is(err, tlspkg.ErrACMENotImplemented) {
		t.Errorf("expected ErrACMENotImplemented, got %v", err)
	}
}
