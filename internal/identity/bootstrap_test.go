package identity_test

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/identity"
)

func TestBootstrap_Run(t *testing.T) {
	repo := identity.NewMemoryPartyRepo()
	auth := identity.NewUserAuthFast()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	bootstrap := identity.NewBootstrap(repo, auth, logger)
	ctx := context.Background()

	admin := identity.SeededUser{
		Username:    "admin",
		Password:    "adminpass",
		DisplayName: "Administrator",
		Role:        "admin",
	}

	seeded := []identity.SeededUser{
		{Username: "alice", Password: "alicepass", Role: "user"},
		{Username: "bob", Password: "bobpass", Role: "user"},
	}

	// First run should create users
	count, err := bootstrap.Run(ctx, admin, seeded)
	if err != nil {
		t.Fatalf("Bootstrap.Run failed: %v", err)
	}
	if count != 3 {
		t.Errorf("expected 3 users created, got %d", count)
	}

	// Verify admin exists
	user, err := repo.GetByUsername(ctx, "admin")
	if err != nil {
		t.Fatalf("admin not found: %v", err)
	}
	if user.Role != "admin" {
		t.Errorf("expected role 'admin', got %q", user.Role)
	}

	// Second run should be idempotent
	count, err = bootstrap.Run(ctx, admin, seeded)
	if err != nil {
		t.Fatalf("Bootstrap.Run (second) failed: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 users created on second run, got %d", count)
	}
}

func TestBootstrap_CreateProbeUser(t *testing.T) {
	repo := identity.NewMemoryPartyRepo()
	auth := identity.NewUserAuthFast()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	bootstrap := identity.NewBootstrap(repo, auth, logger)
	ctx := context.Background()

	// Create probe user
	user, err := bootstrap.CreateProbeUser(ctx, "probe1", "probepass", "test-realm", "/data/probe1")
	if err != nil {
		t.Fatalf("CreateProbeUser failed: %v", err)
	}

	if !user.IsProbe() {
		t.Error("user should be a probe")
	}
	if user.Realm != "test-realm" {
		t.Errorf("expected realm 'test-realm', got %q", user.Realm)
	}
	if user.StorageRoot != "/data/probe1" {
		t.Errorf("expected storage root '/data/probe1', got %q", user.StorageRoot)
	}
	if user.ExpiresAt == nil {
		t.Error("probe user should have expiration")
	}

	// Creating same probe user in same realm should return existing
	user2, err := bootstrap.CreateProbeUser(ctx, "probe1", "probepass", "test-realm", "/data/probe1")
	if err != nil {
		t.Fatalf("CreateProbeUser (second) failed: %v", err)
	}
	if user2.ID != user.ID {
		t.Error("should return existing user")
	}
}
