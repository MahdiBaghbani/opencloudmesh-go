package identity_test

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
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

func TestBootstrap_EnsureSuperAdmin(t *testing.T) {
	repo := identity.NewMemoryPartyRepo()
	auth := identity.NewUserAuthFast()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	bootstrap := identity.NewBootstrap(repo, auth, logger)
	ctx := context.Background()

	// First call creates super admin with explicit password
	err := bootstrap.EnsureSuperAdmin(ctx, "superadmin", "secret123", true)
	if err != nil {
		t.Fatalf("EnsureSuperAdmin failed: %v", err)
	}

	// Verify super admin exists
	user, err := repo.GetByUsername(ctx, "superadmin")
	if err != nil {
		t.Fatalf("super admin not found: %v", err)
	}
	if !user.IsSuperAdmin() {
		t.Errorf("expected role 'super_admin', got %q", user.Role)
	}

	// Second call should be idempotent (no new user)
	err = bootstrap.EnsureSuperAdmin(ctx, "different", "password", true)
	if err != nil {
		t.Fatalf("EnsureSuperAdmin (second) failed: %v", err)
	}

	// Original super admin should still exist
	user, err = repo.GetByUsername(ctx, "superadmin")
	if err != nil {
		t.Fatalf("super admin not found after second call: %v", err)
	}

	// "different" user should not exist (only one super admin)
	_, err = repo.GetByUsername(ctx, "different")
	if err != identity.ErrUserNotFound {
		t.Error("expected no 'different' user to be created")
	}
}

func TestBootstrap_EnsureSuperAdmin_AutoGenPassword(t *testing.T) {
	repo := identity.NewMemoryPartyRepo()
	auth := identity.NewUserAuthFast()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	bootstrap := identity.NewBootstrap(repo, auth, logger)
	ctx := context.Background()

	// Empty password should auto-generate
	err := bootstrap.EnsureSuperAdmin(ctx, "admin", "", false)
	if err != nil {
		t.Fatalf("EnsureSuperAdmin failed: %v", err)
	}

	// Verify super admin exists
	user, err := repo.GetByUsername(ctx, "admin")
	if err != nil {
		t.Fatalf("super admin not found: %v", err)
	}
	if !user.IsSuperAdmin() {
		t.Errorf("expected role 'super_admin', got %q", user.Role)
	}
	// Password hash should be set (we can't verify the actual password)
	if user.PasswordHash == "" {
		t.Error("password hash should be set")
	}
}

func TestSuperAdmin_CannotBeDeleted(t *testing.T) {
	repo := identity.NewMemoryPartyRepo()
	auth := identity.NewUserAuthFast()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	bootstrap := identity.NewBootstrap(repo, auth, logger)
	ctx := context.Background()

	// Create super admin
	err := bootstrap.EnsureSuperAdmin(ctx, "superadmin", "secret", true)
	if err != nil {
		t.Fatalf("EnsureSuperAdmin failed: %v", err)
	}

	// Get super admin
	user, err := repo.GetByUsername(ctx, "superadmin")
	if err != nil {
		t.Fatalf("super admin not found: %v", err)
	}

	// Try to delete - should fail
	err = repo.Delete(ctx, user.ID)
	if err != identity.ErrSuperAdminProtected {
		t.Errorf("expected ErrSuperAdminProtected, got %v", err)
	}
}

func TestSuperAdmin_CannotBeDemoted(t *testing.T) {
	repo := identity.NewMemoryPartyRepo()
	auth := identity.NewUserAuthFast()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	bootstrap := identity.NewBootstrap(repo, auth, logger)
	ctx := context.Background()

	// Create super admin
	err := bootstrap.EnsureSuperAdmin(ctx, "superadmin", "secret", true)
	if err != nil {
		t.Fatalf("EnsureSuperAdmin failed: %v", err)
	}

	// Get super admin
	user, err := repo.GetByUsername(ctx, "superadmin")
	if err != nil {
		t.Fatalf("super admin not found: %v", err)
	}

	// Try to demote to admin - should fail
	user.Role = identity.RoleAdmin
	err = repo.Update(ctx, user)
	if err != identity.ErrSuperAdminRoleChange {
		t.Errorf("expected ErrSuperAdminRoleChange, got %v", err)
	}

	// Try to demote to user - should fail
	user.Role = identity.RoleUser
	err = repo.Update(ctx, user)
	if err != identity.ErrSuperAdminRoleChange {
		t.Errorf("expected ErrSuperAdminRoleChange, got %v", err)
	}
}

func TestSuperAdmin_UsernameCanBeRenamed(t *testing.T) {
	repo := identity.NewMemoryPartyRepo()
	auth := identity.NewUserAuthFast()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	bootstrap := identity.NewBootstrap(repo, auth, logger)
	ctx := context.Background()

	// Create super admin
	err := bootstrap.EnsureSuperAdmin(ctx, "superadmin", "secret", true)
	if err != nil {
		t.Fatalf("EnsureSuperAdmin failed: %v", err)
	}

	// Get super admin
	user, err := repo.GetByUsername(ctx, "superadmin")
	if err != nil {
		t.Fatalf("super admin not found: %v", err)
	}
	originalID := user.ID

	// Rename username - should succeed
	user.Username = "root"
	err = repo.Update(ctx, user)
	if err != nil {
		t.Fatalf("renaming super admin failed: %v", err)
	}

	// Old username should not exist
	_, err = repo.GetByUsername(ctx, "superadmin")
	if err != identity.ErrUserNotFound {
		t.Error("old username should not exist")
	}

	// New username should exist with same ID
	user, err = repo.GetByUsername(ctx, "root")
	if err != nil {
		t.Fatalf("new username not found: %v", err)
	}
	if user.ID != originalID {
		t.Error("user ID should remain the same after rename")
	}
	if !user.IsSuperAdmin() {
		t.Error("user should still be super admin after rename")
	}
}
