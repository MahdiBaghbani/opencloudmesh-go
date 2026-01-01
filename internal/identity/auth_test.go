package identity_test

import (
	"context"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/identity"
)

func TestUserAuth_HashAndVerify(t *testing.T) {
	auth := identity.NewUserAuth(4) // Low cost for fast tests

	password := "secret123"
	hash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	if hash == password {
		t.Error("hash should not equal password")
	}

	// Correct password
	if err := auth.VerifyPassword(hash, password); err != nil {
		t.Errorf("VerifyPassword failed for correct password: %v", err)
	}

	// Wrong password
	err = auth.VerifyPassword(hash, "wrongpassword")
	if err != identity.ErrInvalidPassword {
		t.Errorf("expected ErrInvalidPassword, got %v", err)
	}
}

func TestUserAuth_Authenticate(t *testing.T) {
	repo := identity.NewMemoryPartyRepo()
	auth := identity.NewUserAuth(4)
	ctx := context.Background()

	// Create a user
	hash, _ := auth.HashPassword("testpass")
	user := &identity.User{
		Username:     "testuser",
		PasswordHash: hash,
		Role:         "user",
	}
	repo.Create(ctx, user)

	// Successful auth
	got, err := auth.Authenticate(ctx, repo, "testuser", "testpass")
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}
	if got.Username != "testuser" {
		t.Errorf("expected username 'testuser', got %q", got.Username)
	}

	// Wrong password
	_, err = auth.Authenticate(ctx, repo, "testuser", "wrongpass")
	if err != identity.ErrInvalidPassword {
		t.Errorf("expected ErrInvalidPassword, got %v", err)
	}

	// Unknown user
	_, err = auth.Authenticate(ctx, repo, "unknown", "testpass")
	if err != identity.ErrUserNotFound {
		t.Errorf("expected ErrUserNotFound, got %v", err)
	}
}
