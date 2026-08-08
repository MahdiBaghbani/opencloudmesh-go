// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package identity_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
)

func TestUserAuth_HashAndVerify(t *testing.T) {
	t.Parallel()

	auth := identity.NewUserAuthFast() // Fast params for tests

	password := "secret123"

	hash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	if hash == password {
		t.Error("hash should not equal password")
	}

	// Verify PHC format
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Errorf("expected argon2id PHC format, got %q", hash)
	}

	// Correct password
	if verr := auth.VerifyPassword(hash, password); verr != nil {
		t.Errorf("VerifyPassword failed for correct password: %v", verr)
	}

	// Wrong password
	err = auth.VerifyPassword(hash, "wrongpassword")
	if !errors.Is(err, identity.ErrInvalidPassword) {
		t.Errorf("expected ErrInvalidPassword, got %v", err)
	}
}

func TestUserAuth_Authenticate(t *testing.T) {
	t.Parallel()

	repo := identity.NewMemoryPartyRepo()
	auth := identity.NewUserAuthFast()
	ctx := context.Background()

	// Create a user
	hash, err := auth.HashPassword("testpass")
	if err != nil {
		t.Fatalf("call failed: %v", err)
	}

	user := &identity.User{
		Username:     "testuser",
		PasswordHash: hash,
		Role:         "user",
	}
	if serr := repo.Create(ctx, user); serr != nil {
		t.Fatalf("Create: %v", serr)
	}

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
	if !errors.Is(err, identity.ErrInvalidPassword) {
		t.Errorf("expected ErrInvalidPassword, got %v", err)
	}

	// Unknown user
	_, err = auth.Authenticate(ctx, repo, "unknown", "testpass")
	if !errors.Is(err, identity.ErrUserNotFound) {
		t.Errorf("expected ErrUserNotFound, got %v", err)
	}
}
