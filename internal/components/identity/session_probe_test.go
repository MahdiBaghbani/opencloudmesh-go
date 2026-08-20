// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package identity_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/keyid"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/localidentity"
	tslocalidentity "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/localidentity"
)

func TestCreateSessionProbeUser_ReusesExisting(t *testing.T) {
	t.Parallel()

	repo := identity.NewMemoryPartyRepo()
	auth := identity.NewUserAuthFast()
	ctx := t.Context()
	spec, localID, keyManager := sessionProbeSpec(t)

	first, err := identity.CreateSessionProbeUser(ctx, repo, auth, spec)
	if err != nil {
		t.Fatalf("CreateSessionProbeUser: %v", err)
	}

	assertSessionProbeUser(t, first, spec, localID, keyManager)

	second, err := identity.CreateSessionProbeUser(ctx, repo, auth, spec)
	if err != nil {
		t.Fatalf("CreateSessionProbeUser reuse: %v", err)
	}

	if second.ID != first.ID {
		t.Fatalf("reused probe ID = %q, want %q", second.ID, first.ID)
	}

	if second.ExpiresAt != nil {
		t.Fatal("username-reused probe ExpiresAt must be nil")
	}

	users, err := repo.List(ctx, "")
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	if len(users) != 1 {
		t.Fatalf("users after reuse = %d, want 1", len(users))
	}
}

func TestCreateSessionProbeUser_DeleteExpiredIsNoOp(t *testing.T) {
	t.Parallel()

	repo := identity.NewMemoryPartyRepo()
	auth := identity.NewUserAuthFast()
	ctx := t.Context()
	spec, _, _ := sessionProbeSpec(t)

	probe, err := identity.CreateSessionProbeUser(ctx, repo, auth, spec)
	if err != nil {
		t.Fatalf("CreateSessionProbeUser: %v", err)
	}

	if probe.ExpiresAt != nil {
		t.Fatal("session probe ExpiresAt must be nil")
	}

	past := time.Now().Add(-time.Hour)
	expired := &identity.User{Username: "expired-probe", Role: identity.RoleProbe, ExpiresAt: &past}

	if createErr := repo.Create(ctx, expired); createErr != nil {
		t.Fatalf("Create expired probe: %v", createErr)
	}

	count, err := repo.DeleteExpired(ctx)
	if err != nil {
		t.Fatalf("DeleteExpired: %v", err)
	}

	if count != 1 {
		t.Fatalf("DeleteExpired count = %d, want 1", count)
	}

	got, err := repo.Get(ctx, probe.ID)
	if err != nil {
		t.Fatalf("Get session probe after DeleteExpired: %v", err)
	}

	if got.ID != probe.ID {
		t.Fatalf("session probe ID = %q, want %q", got.ID, probe.ID)
	}
}

func TestCreateSessionProbeUser_TTLBearingProbeIsNotReturnedWithTTL(t *testing.T) {
	t.Parallel()

	repo := identity.NewMemoryPartyRepo()
	auth := identity.NewUserAuthFast()
	ctx := t.Context()
	spec, localID, keyManager := sessionProbeSpec(t)
	past := time.Now().Add(-time.Hour)

	ttlProbe := &identity.User{
		Username:    identity.SessionProbeUsername,
		Email:       spec.Email,
		DisplayName: spec.DisplayName,
		Role:        identity.RoleProbe,
		Realm:       spec.Realm,
		ExpiresAt:   &past,
	}
	if err := repo.Create(ctx, ttlProbe); err != nil {
		t.Fatalf("Create TTL probe: %v", err)
	}

	got, err := identity.CreateSessionProbeUser(ctx, repo, auth, spec)
	if err != nil {
		t.Fatalf("CreateSessionProbeUser: %v", err)
	}

	if got.ExpiresAt != nil {
		t.Fatal("reused TTL-bearing probe must not be returned with ExpiresAt set")
	}

	if got.ID != ttlProbe.ID {
		t.Fatalf("replaced probe ID = %q, want %q", got.ID, ttlProbe.ID)
	}

	assertSessionProbeUser(t, got, spec, localID, keyManager)

	count, err := repo.DeleteExpired(ctx)
	if err != nil {
		t.Fatalf("DeleteExpired: %v", err)
	}

	if count != 0 {
		t.Fatalf("DeleteExpired count = %d, want 0 on session probe", count)
	}

	stored, err := repo.Get(ctx, got.ID)
	if err != nil {
		t.Fatalf("Get after DeleteExpired: %v", err)
	}

	if stored.ExpiresAt != nil {
		t.Fatal("stored session probe ExpiresAt must stay nil")
	}
}

func TestCreateSessionProbeUser_ReusesByEmail(t *testing.T) {
	t.Parallel()

	repo := identity.NewMemoryPartyRepo()
	auth := identity.NewUserAuthFast()
	ctx := t.Context()
	spec, _, _ := sessionProbeSpec(t)

	existing := &identity.User{
		Username:    "email-probe",
		Email:       spec.Email,
		DisplayName: spec.DisplayName,
		Role:        identity.RoleProbe,
		Realm:       spec.Realm,
	}
	if err := repo.Create(ctx, existing); err != nil {
		t.Fatalf("Create email probe: %v", err)
	}

	got, err := identity.CreateSessionProbeUser(ctx, repo, auth, spec)
	if err != nil {
		t.Fatalf("CreateSessionProbeUser: %v", err)
	}

	if got.ID != existing.ID {
		t.Fatalf("email reuse ID = %q, want %q", got.ID, existing.ID)
	}

	if got.ExpiresAt != nil {
		t.Fatal("email-reused probe ExpiresAt must be nil")
	}
}

func TestCreateSessionProbeUser_TTLBearingEmailProbeIsNotReturnedWithTTL(t *testing.T) {
	t.Parallel()

	repo := identity.NewMemoryPartyRepo()
	auth := identity.NewUserAuthFast()
	ctx := t.Context()
	spec, _, _ := sessionProbeSpec(t)
	past := time.Now().Add(-time.Hour)

	ttlProbe := &identity.User{
		Username:    "email-ttl-probe",
		Email:       spec.Email,
		DisplayName: spec.DisplayName,
		Role:        identity.RoleProbe,
		Realm:       spec.Realm,
		ExpiresAt:   &past,
	}
	if err := repo.Create(ctx, ttlProbe); err != nil {
		t.Fatalf("Create TTL email probe: %v", err)
	}

	got, err := identity.CreateSessionProbeUser(ctx, repo, auth, spec)
	if err != nil {
		t.Fatalf("CreateSessionProbeUser: %v", err)
	}

	if got.ID != ttlProbe.ID {
		t.Fatalf("email TTL reuse ID = %q, want %q", got.ID, ttlProbe.ID)
	}

	if got.ExpiresAt != nil {
		t.Fatal("email TTL reuse must not return ExpiresAt set")
	}

	count, err := repo.DeleteExpired(ctx)
	if err != nil {
		t.Fatalf("DeleteExpired: %v", err)
	}

	if count != 0 {
		t.Fatalf("DeleteExpired count = %d, want 0", count)
	}
}

func TestCreateSessionProbeUser_UsernameConflict(t *testing.T) {
	t.Parallel()

	repo := identity.NewMemoryPartyRepo()
	auth := identity.NewUserAuthFast()
	ctx := t.Context()
	spec, _, _ := sessionProbeSpec(t)

	occupant := &identity.User{
		Username: identity.SessionProbeUsername,
		Role:     identity.RoleUser,
	}
	if err := repo.Create(ctx, occupant); err != nil {
		t.Fatalf("Create occupant: %v", err)
	}

	_, err := identity.CreateSessionProbeUser(ctx, repo, auth, spec)
	if !errors.Is(err, identity.ErrUserExists) {
		t.Fatalf("error = %v, want ErrUserExists", err)
	}
}

func TestCreateSessionProbeUser_EmailConflict(t *testing.T) {
	t.Parallel()

	t.Run("create_conflict_non_probe", func(t *testing.T) {
		t.Parallel()

		repo, spec := hiddenEmailRepo(t, &identity.User{Username: "alice", Role: identity.RoleUser})

		_, err := identity.CreateSessionProbeUser(t.Context(), repo, identity.NewUserAuthFast(), spec)
		if !errors.Is(err, identity.ErrEmailExists) {
			t.Fatalf("error = %v, want ErrEmailExists", err)
		}

		if repo.creates != 1 {
			t.Fatalf("Create calls = %d, want 1 (create-conflict)", repo.creates)
		}
	})

	t.Run("create_conflict_reuses_probe", func(t *testing.T) {
		t.Parallel()

		past := time.Now().Add(-time.Hour)
		occupant := &identity.User{Username: "alice", Role: identity.RoleProbe, ExpiresAt: &past}
		repo, spec := hiddenEmailRepo(t, occupant)

		got, err := identity.CreateSessionProbeUser(t.Context(), repo, identity.NewUserAuthFast(), spec)
		if err != nil {
			t.Fatalf("CreateSessionProbeUser create-conflict: %v", err)
		}

		if repo.creates != 1 || got.ID != occupant.ID || got.ExpiresAt != nil {
			t.Fatalf("conflict reuse creates=%d id=%q expires=%v", repo.creates, got.ID, got.ExpiresAt)
		}
	})
}

func TestCreateSessionProbeUser_RealmMismatchRejected(t *testing.T) {
	t.Parallel()

	repo := identity.NewMemoryPartyRepo()
	auth := identity.NewUserAuthFast()
	ctx := t.Context()
	spec, _, _ := sessionProbeSpec(t)

	existing := &identity.User{
		Username: identity.SessionProbeUsername,
		Email:    spec.Email,
		Role:     identity.RoleProbe,
		Realm:    "other.example",
	}
	if err := repo.Create(ctx, existing); err != nil {
		t.Fatalf("Create other-realm probe: %v", err)
	}

	_, err := identity.CreateSessionProbeUser(ctx, repo, auth, spec)
	if !errors.Is(err, identity.ErrSessionProbeRealmMismatch) {
		t.Fatalf("error = %v, want ErrSessionProbeRealmMismatch", err)
	}
}

func sessionProbeSpec(t *testing.T) (
	identity.SessionProbeUserSpec,
	localidentity.Identity,
	*crypto.KeyManager,
) {
	t.Helper()

	localID, keyManager := sessionProbeSharedKeyManager(t)

	testRunID, err := identity.UUIDv7()
	if err != nil {
		t.Fatalf("mint production TestRunID: %v", err)
	}

	return identity.SessionProbeUserSpec{
		Email:       config.DefaultValidatorProbeEmail,
		DisplayName: config.DefaultValidatorProbeDisplayName,
		Realm:       localID.ProviderDomain,
		TestRunID:   testRunID,
	}, localID, keyManager
}

func sessionProbeSharedKeyManager(t *testing.T) (localidentity.Identity, *crypto.KeyManager) {
	t.Helper()

	const publicOrigin = "https://validator.example:9200"

	localID := tslocalidentity.MustTestIdentity(t, publicOrigin, "")
	sig := config.DefaultSignatureConfig()
	keyManager := crypto.NewKeyManagerWithFragment("", localID.Origin, sig.KidFragment)

	if err := keyManager.LoadOrGenerate(); err != nil {
		t.Fatalf("shared KeyManager LoadOrGenerate: %v", err)
	}

	return localID, keyManager
}

func assertSessionProbeUser(
	t *testing.T,
	user *identity.User,
	spec identity.SessionProbeUserSpec,
	localID localidentity.Identity,
	keyManager *crypto.KeyManager,
) {
	t.Helper()

	if user == nil {
		t.Fatal("expected session probe user")
	}

	if !user.IsProbe() {
		t.Fatalf("role = %q, want probe", user.Role)
	}

	if user.Username != identity.SessionProbeUsername {
		t.Fatalf("username = %q, want %q", user.Username, identity.SessionProbeUsername)
	}

	if user.Email != spec.Email {
		t.Fatalf("email = %q, want %q", user.Email, spec.Email)
	}

	if user.DisplayName != spec.DisplayName {
		t.Fatalf("display name = %q, want %q", user.DisplayName, spec.DisplayName)
	}

	if user.Realm != spec.Realm {
		t.Fatalf("realm = %q, want %q", user.Realm, spec.Realm)
	}

	if user.ExpiresAt != nil {
		t.Fatal("session probe ExpiresAt must be nil")
	}

	if spec.TestRunID == "" || len(spec.TestRunID) != 36 || spec.TestRunID[14] != '7' {
		t.Fatalf("TestRunID %q is not a real minted UUIDv7", spec.TestRunID)
	}

	if user.ID == "" || user.ID == spec.TestRunID || len(user.ID) != 36 || user.ID[14] != '7' {
		t.Fatalf("minted probe ID %q must be a UUIDv7 distinct from TestRunID %q", user.ID, spec.TestRunID)
	}

	assertSharedKeyManager(t, user, localID, keyManager)
}

func assertSharedKeyManager(
	t *testing.T,
	user *identity.User,
	localID localidentity.Identity,
	keyManager *crypto.KeyManager,
) {
	t.Helper()

	if keyManager == nil {
		t.Fatal("expected production shared KeyManager")
	}

	if user.Realm != localID.ProviderDomain {
		t.Fatalf("probe realm = %q, want shared local provider domain %q", user.Realm, localID.ProviderDomain)
	}

	wantKid, err := keyid.KidFromPublicOrigin(localID.Origin, config.DefaultSignatureConfig().KidFragment)
	if err != nil {
		t.Fatalf("KidFromPublicOrigin: %v", err)
	}

	if keyManager.GetKeyID() != wantKid {
		t.Fatalf("shared KeyManager kid = %q, want derived %q", keyManager.GetKeyID(), wantKid)
	}

	signing := keyManager.GetSigningKey()
	if signing == nil {
		t.Fatal("expected shared KeyManager to hold a derived signing key")
	}

	if signing.KeyID != wantKid {
		t.Fatalf("derived signing key id = %q, want %q", signing.KeyID, wantKid)
	}
}

func hiddenEmailRepo(
	t *testing.T,
	occupant *identity.User,
) (*hideEmailUntilCreateRepo, identity.SessionProbeUserSpec) {
	t.Helper()

	inner := identity.NewMemoryPartyRepo()
	repo := &hideEmailUntilCreateRepo{MemoryPartyRepo: inner}
	spec, _, _ := sessionProbeSpec(t)
	occupant.Email = spec.Email

	if occupant.IsProbe() {
		occupant.Realm = spec.Realm
	}

	if err := inner.Create(t.Context(), occupant); err != nil {
		t.Fatalf("Create occupant: %v", err)
	}

	return repo, spec
}

type hideEmailUntilCreateRepo struct {
	*identity.MemoryPartyRepo

	creates int
}

func (r *hideEmailUntilCreateRepo) GetByEmail(
	ctx context.Context,
	email string,
) (*identity.User, error) {
	if r.creates == 0 {
		return nil, identity.ErrUserNotFound
	}

	user, err := r.MemoryPartyRepo.GetByEmail(ctx, email)
	if err != nil {
		return nil, fmt.Errorf("hidden email repo: %w", err)
	}

	return user, nil
}

func (r *hideEmailUntilCreateRepo) Create(ctx context.Context, user *identity.User) error {
	err := r.MemoryPartyRepo.Create(ctx, user)
	r.creates++

	if err != nil {
		return fmt.Errorf("hidden email repo: %w", err)
	}

	return nil
}
