package identity_test

import (
	"context"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
)

func TestMemorySessionRepo_CRUD(t *testing.T) {
	repo := identity.NewMemorySessionRepo()
	ctx := context.Background()

	// Create session
	session, err := repo.Create(ctx, "user-123", time.Hour)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if session.Token == "" {
		t.Error("token should be assigned")
	}
	if session.UserID != "user-123" {
		t.Errorf("expected userID 'user-123', got %q", session.UserID)
	}

	// Get session
	got, err := repo.Get(ctx, session.Token)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if got.UserID != "user-123" {
		t.Errorf("expected userID 'user-123', got %q", got.UserID)
	}

	// Delete session
	if err := repo.Delete(ctx, session.Token); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Get should fail after delete
	_, err = repo.Get(ctx, session.Token)
	if err != identity.ErrSessionNotFound {
		t.Errorf("expected ErrSessionNotFound, got %v", err)
	}
}

func TestMemorySessionRepo_ExpiredSession(t *testing.T) {
	repo := identity.NewMemorySessionRepo()
	ctx := context.Background()

	// Create a session with very short TTL
	session, err := repo.Create(ctx, "user-123", time.Millisecond)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Wait for expiration
	time.Sleep(10 * time.Millisecond)

	// Get should return expired error
	_, err = repo.Get(ctx, session.Token)
	if err != identity.ErrSessionExpired {
		t.Errorf("expected ErrSessionExpired, got %v", err)
	}
}

func TestMemorySessionRepo_DeleteByUser(t *testing.T) {
	repo := identity.NewMemorySessionRepo()
	ctx := context.Background()

	// Create multiple sessions for same user
	s1, _ := repo.Create(ctx, "user-123", time.Hour)
	s2, _ := repo.Create(ctx, "user-123", time.Hour)

	// Delete all sessions for user
	if err := repo.DeleteByUser(ctx, "user-123"); err != nil {
		t.Fatalf("DeleteByUser failed: %v", err)
	}

	// Both sessions should be gone
	_, err := repo.Get(ctx, s1.Token)
	if err != identity.ErrSessionNotFound {
		t.Errorf("expected ErrSessionNotFound for s1, got %v", err)
	}
	_, err = repo.Get(ctx, s2.Token)
	if err != identity.ErrSessionNotFound {
		t.Errorf("expected ErrSessionNotFound for s2, got %v", err)
	}
}

func TestMemorySessionRepo_DeleteExpired(t *testing.T) {
	repo := identity.NewMemorySessionRepo()
	ctx := context.Background()

	// Create a session that will expire immediately
	repo.Create(ctx, "user-123", time.Millisecond)
	time.Sleep(10 * time.Millisecond)

	// Create a session that won't expire
	s2, _ := repo.Create(ctx, "user-456", time.Hour)

	// Delete expired
	count, err := repo.DeleteExpired(ctx)
	if err != nil {
		t.Fatalf("DeleteExpired failed: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 expired session, got %d", count)
	}

	// Valid session should still work
	_, err = repo.Get(ctx, s2.Token)
	if err != nil {
		t.Errorf("valid session should still exist: %v", err)
	}
}

func TestGenerateToken(t *testing.T) {
	t1, err := identity.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	t2, err := identity.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	if t1 == t2 {
		t.Error("tokens should be unique")
	}

	// Should be base64 URL encoded (43 chars for 32 bytes)
	if len(t1) < 40 {
		t.Errorf("token too short: %d", len(t1))
	}
}
