package server

import (
	"errors"
	"log/slog"
	"os"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/httpclient"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/identity"
)

func TestNew_FailsWithNilDeps(t *testing.T) {
	cfg := config.DevConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	_, err := New(cfg, logger, nil, nil, nil, nil, nil, nil, nil) // nil services acceptable for tests
	if err == nil {
		t.Fatal("expected error for nil deps")
	}
}

func TestNew_FailsWithMissingPartyRepo(t *testing.T) {
	cfg := config.DevConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	deps := &Deps{
		SessionRepo: identity.NewMemorySessionRepo(),
		UserAuth:    identity.NewUserAuth(1),
		HTTPClient:  httpclient.NewContextClient(httpclient.New(nil)),
	}

	_, err := New(cfg, logger, deps, nil, nil, nil, nil, nil, nil) // nil services acceptable for tests
	if err == nil {
		t.Fatal("expected error for missing PartyRepo")
	}
	if !errors.Is(err, ErrMissingDep) {
		t.Errorf("expected ErrMissingDep, got: %v", err)
	}
}

func TestNew_FailsWithMissingSessionRepo(t *testing.T) {
	cfg := config.DevConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	deps := &Deps{
		PartyRepo:  identity.NewMemoryPartyRepo(),
		UserAuth:   identity.NewUserAuth(1),
		HTTPClient: httpclient.NewContextClient(httpclient.New(nil)),
	}

	_, err := New(cfg, logger, deps, nil, nil, nil, nil, nil, nil)
	if err == nil {
		t.Fatal("expected error for missing SessionRepo")
	}
	if !errors.Is(err, ErrMissingDep) {
		t.Errorf("expected ErrMissingDep, got: %v", err)
	}
}

func TestNew_FailsWithMissingUserAuth(t *testing.T) {
	cfg := config.DevConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	deps := &Deps{
		PartyRepo:   identity.NewMemoryPartyRepo(),
		SessionRepo: identity.NewMemorySessionRepo(),
		HTTPClient:  httpclient.NewContextClient(httpclient.New(nil)),
	}

	_, err := New(cfg, logger, deps, nil, nil, nil, nil, nil, nil)
	if err == nil {
		t.Fatal("expected error for missing UserAuth")
	}
	if !errors.Is(err, ErrMissingDep) {
		t.Errorf("expected ErrMissingDep, got: %v", err)
	}
}

func TestNew_FailsWithMissingHTTPClient(t *testing.T) {
	cfg := config.DevConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	deps := &Deps{
		PartyRepo:   identity.NewMemoryPartyRepo(),
		SessionRepo: identity.NewMemorySessionRepo(),
		UserAuth:    identity.NewUserAuth(1),
	}

	_, err := New(cfg, logger, deps, nil, nil, nil, nil, nil, nil)
	if err == nil {
		t.Fatal("expected error for missing HTTPClient")
	}
	if !errors.Is(err, ErrMissingDep) {
		t.Errorf("expected ErrMissingDep, got: %v", err)
	}
}

func TestNew_SucceedsWithRequiredDeps(t *testing.T) {
	cfg := config.DevConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	deps := &Deps{
		PartyRepo:   identity.NewMemoryPartyRepo(),
		SessionRepo: identity.NewMemorySessionRepo(),
		UserAuth:    identity.NewUserAuth(1),
		HTTPClient:  httpclient.NewContextClient(httpclient.New(nil)),
	}

	srv, err := New(cfg, logger, deps, nil, nil, nil, nil, nil, nil) // nil services acceptable for tests
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if srv == nil {
		t.Fatal("expected non-nil server")
	}
}
