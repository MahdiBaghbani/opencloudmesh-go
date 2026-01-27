package identity_test

import (
	"context"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
)

func TestMemoryPartyRepo_CRUD(t *testing.T) {
	repo := identity.NewMemoryPartyRepo()
	ctx := context.Background()

	user := &identity.User{
		Username:     "alice",
		Email:        "alice@example.com",
		DisplayName:  "Alice Smith",
		PasswordHash: "hashed",
		Role:         "user",
		Realm:        "default",
		StorageRoot:  "/data/alice",
	}

	// Create
	if err := repo.Create(ctx, user); err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if user.ID == "" {
		t.Error("ID should be assigned on create")
	}

	// Get by ID
	got, err := repo.Get(ctx, user.ID)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if got.Username != "alice" {
		t.Errorf("expected username 'alice', got %q", got.Username)
	}

	// Get by username
	got, err = repo.GetByUsername(ctx, "alice")
	if err != nil {
		t.Fatalf("GetByUsername failed: %v", err)
	}
	if got.ID != user.ID {
		t.Errorf("ID mismatch")
	}

	// Update
	user.DisplayName = "Alice Updated"
	if err := repo.Update(ctx, user); err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	got, _ = repo.Get(ctx, user.ID)
	if got.DisplayName != "Alice Updated" {
		t.Errorf("expected updated display name")
	}

	// List
	users, err := repo.List(ctx, "")
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(users) != 1 {
		t.Errorf("expected 1 user, got %d", len(users))
	}

	// Delete
	if err := repo.Delete(ctx, user.ID); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	_, err = repo.Get(ctx, user.ID)
	if err != identity.ErrUserNotFound {
		t.Errorf("expected ErrUserNotFound after delete")
	}
}

func TestMemoryPartyRepo_DuplicateUsername(t *testing.T) {
	repo := identity.NewMemoryPartyRepo()
	ctx := context.Background()

	user1 := &identity.User{Username: "alice", Role: "user"}
	user2 := &identity.User{Username: "alice", Role: "user"}

	if err := repo.Create(ctx, user1); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	err := repo.Create(ctx, user2)
	if err != identity.ErrUserExists {
		t.Errorf("expected ErrUserExists, got %v", err)
	}
}

func TestMemoryPartyRepo_DeleteExpired(t *testing.T) {
	repo := identity.NewMemoryPartyRepo()
	ctx := context.Background()

	// Create a user that is already expired
	past := time.Now().Add(-time.Hour)
	user := &identity.User{
		Username:  "probe1",
		Role:      "probe",
		ExpiresAt: &past,
	}
	if err := repo.Create(ctx, user); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Create a non-expired user
	future := time.Now().Add(time.Hour)
	user2 := &identity.User{
		Username:  "probe2",
		Role:      "probe",
		ExpiresAt: &future,
	}
	if err := repo.Create(ctx, user2); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Delete expired
	count, err := repo.DeleteExpired(ctx)
	if err != nil {
		t.Fatalf("DeleteExpired failed: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 expired user deleted, got %d", count)
	}

	// Verify only non-expired remains
	users, _ := repo.List(ctx, "")
	if len(users) != 1 {
		t.Errorf("expected 1 user remaining, got %d", len(users))
	}
	if users[0].Username != "probe2" {
		t.Errorf("wrong user remained")
	}
}

func TestMemoryPartyRepo_GetByEmail(t *testing.T) {
	repo := identity.NewMemoryPartyRepo()
	ctx := context.Background()

	user := &identity.User{
		Username: "alice",
		Email:    "Alice@Example.COM",
		Role:     "user",
	}
	if err := repo.Create(ctx, user); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Lookup by exact email
	got, err := repo.GetByEmail(ctx, "Alice@Example.COM")
	if err != nil {
		t.Fatalf("GetByEmail exact failed: %v", err)
	}
	if got.ID != user.ID {
		t.Errorf("ID mismatch: got %q, want %q", got.ID, user.ID)
	}

	// Lookup is case-insensitive and trims whitespace
	got, err = repo.GetByEmail(ctx, "  alice@example.com  ")
	if err != nil {
		t.Fatalf("GetByEmail normalized failed: %v", err)
	}
	if got.ID != user.ID {
		t.Error("expected same user from case-insensitive email lookup")
	}

	// Unknown email returns ErrUserNotFound
	_, err = repo.GetByEmail(ctx, "bob@example.com")
	if err != identity.ErrUserNotFound {
		t.Errorf("expected ErrUserNotFound, got %v", err)
	}

	// Empty email returns ErrUserNotFound (not indexed)
	_, err = repo.GetByEmail(ctx, "")
	if err != identity.ErrUserNotFound {
		t.Errorf("expected ErrUserNotFound for empty email, got %v", err)
	}
}

func TestMemoryPartyRepo_DuplicateEmail(t *testing.T) {
	repo := identity.NewMemoryPartyRepo()
	ctx := context.Background()

	user1 := &identity.User{Username: "alice", Email: "shared@example.com", Role: "user"}
	user2 := &identity.User{Username: "bob", Email: "SHARED@Example.COM", Role: "user"}

	if err := repo.Create(ctx, user1); err != nil {
		t.Fatalf("Create user1 failed: %v", err)
	}

	err := repo.Create(ctx, user2)
	if err != identity.ErrEmailExists {
		t.Errorf("expected ErrEmailExists for duplicate email, got %v", err)
	}
}

func TestMemoryPartyRepo_EmptyEmailNotIndexed(t *testing.T) {
	repo := identity.NewMemoryPartyRepo()
	ctx := context.Background()

	// Two users with empty emails should not conflict
	user1 := &identity.User{Username: "alice", Email: "", Role: "user"}
	user2 := &identity.User{Username: "bob", Email: "", Role: "user"}

	if err := repo.Create(ctx, user1); err != nil {
		t.Fatalf("Create user1 failed: %v", err)
	}
	if err := repo.Create(ctx, user2); err != nil {
		t.Fatalf("Create user2 failed: %v", err)
	}

	// Whitespace-only email is treated as empty (not indexed)
	user3 := &identity.User{Username: "carol", Email: "  ", Role: "user"}
	if err := repo.Create(ctx, user3); err != nil {
		t.Fatalf("Create user3 with whitespace email failed: %v", err)
	}
}

func TestMemoryPartyRepo_UpdateMaintainsEmailIndex(t *testing.T) {
	repo := identity.NewMemoryPartyRepo()
	ctx := context.Background()

	user := &identity.User{
		Username: "alice",
		Email:    "alice@example.com",
		Role:     "user",
	}
	if err := repo.Create(ctx, user); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Change email
	user.Email = "newalice@example.com"
	if err := repo.Update(ctx, user); err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	// Old email should not resolve
	_, err := repo.GetByEmail(ctx, "alice@example.com")
	if err != identity.ErrUserNotFound {
		t.Errorf("expected ErrUserNotFound for old email, got %v", err)
	}

	// New email should resolve
	got, err := repo.GetByEmail(ctx, "newalice@example.com")
	if err != nil {
		t.Fatalf("GetByEmail for new email failed: %v", err)
	}
	if got.ID != user.ID {
		t.Error("ID mismatch after email update")
	}

	// Update to empty email removes from index
	user.Email = ""
	if err := repo.Update(ctx, user); err != nil {
		t.Fatalf("Update to empty email failed: %v", err)
	}
	_, err = repo.GetByEmail(ctx, "newalice@example.com")
	if err != identity.ErrUserNotFound {
		t.Errorf("expected ErrUserNotFound after clearing email, got %v", err)
	}
}

func TestMemoryPartyRepo_UpdateEmailUniqueness(t *testing.T) {
	repo := identity.NewMemoryPartyRepo()
	ctx := context.Background()

	user1 := &identity.User{Username: "alice", Email: "alice@example.com", Role: "user"}
	user2 := &identity.User{Username: "bob", Email: "bob@example.com", Role: "user"}

	if err := repo.Create(ctx, user1); err != nil {
		t.Fatalf("Create user1 failed: %v", err)
	}
	if err := repo.Create(ctx, user2); err != nil {
		t.Fatalf("Create user2 failed: %v", err)
	}

	// Bob tries to take Alice's email
	user2.Email = "alice@example.com"
	err := repo.Update(ctx, user2)
	if err != identity.ErrEmailExists {
		t.Errorf("expected ErrEmailExists, got %v", err)
	}
}

func TestMemoryPartyRepo_DeleteRemovesEmailIndex(t *testing.T) {
	repo := identity.NewMemoryPartyRepo()
	ctx := context.Background()

	user := &identity.User{Username: "alice", Email: "alice@example.com", Role: "user"}
	if err := repo.Create(ctx, user); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Delete user
	if err := repo.Delete(ctx, user.ID); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Email should no longer resolve
	_, err := repo.GetByEmail(ctx, "alice@example.com")
	if err != identity.ErrUserNotFound {
		t.Errorf("expected ErrUserNotFound after delete, got %v", err)
	}

	// Another user can now use the same email
	user2 := &identity.User{Username: "bob", Email: "alice@example.com", Role: "user"}
	if err := repo.Create(ctx, user2); err != nil {
		t.Fatalf("Create with freed email failed: %v", err)
	}
}

func TestUUIDv7(t *testing.T) {
	id1 := identity.UUIDv7()
	id2 := identity.UUIDv7()

	if id1 == id2 {
		t.Error("UUIDs should be unique")
	}

	// Check format (8-4-4-4-12)
	if len(id1) != 36 {
		t.Errorf("expected length 36, got %d", len(id1))
	}
	if id1[8] != '-' || id1[13] != '-' || id1[18] != '-' || id1[23] != '-' {
		t.Error("invalid UUID format")
	}

	// Check version nibble (should be 7)
	if id1[14] != '7' {
		t.Errorf("expected version 7, got %c", id1[14])
	}
}
