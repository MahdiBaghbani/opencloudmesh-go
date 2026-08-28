// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package identity_test

import (
	"errors"
	"sync"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

func TestEnsureParty_CreateOrGetByPrescribedID(t *testing.T) {
	t.Parallel()

	repo := identity.NewMemoryPartyRepo()
	ctx := t.Context()
	spec := identity.PartySpec{
		ID:          "party-1",
		Username:    "user-party-1",
		Email:       "party-1@example.com",
		DisplayName: "Party One",
		Role:        identity.RoleProbe,
		Realm:       "local.example",
	}

	first, err := identity.EnsureParty(ctx, repo, spec)
	if err != nil {
		t.Fatalf("EnsureParty create: %v", err)
	}

	if first.ID != spec.ID || first.Username != spec.Username || first.ExpiresAt != nil {
		t.Fatalf("created party = %+v", first)
	}

	second, err := identity.EnsureParty(ctx, repo, spec)
	if err != nil {
		t.Fatalf("EnsureParty get: %v", err)
	}

	if second.ID != first.ID {
		t.Fatalf("reused ID = %q, want %q", second.ID, first.ID)
	}

	users, err := repo.List(ctx, "")
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	if len(users) != 1 {
		t.Fatalf("users = %d, want 1", len(users))
	}
}

func TestEnsureParty_UsernameCollisionDifferentID(t *testing.T) {
	t.Parallel()

	repo := identity.NewMemoryPartyRepo()
	ctx := t.Context()

	if err := repo.Create(ctx, &identity.User{
		ID:       "occupant",
		Username: "shared-name",
		Role:     identity.RoleUser,
	}); err != nil {
		t.Fatalf("Create occupant: %v", err)
	}

	_, err := identity.EnsureParty(ctx, repo, identity.PartySpec{
		ID:       "prescribed",
		Username: "shared-name",
		Role:     identity.RoleProbe,
	})
	if !errors.Is(err, identity.ErrUserExists) {
		t.Fatalf("error = %v, want ErrUserExists", err)
	}

	got, err := repo.Get(ctx, "occupant")
	if err != nil {
		t.Fatalf("Get occupant: %v", err)
	}

	if got.Username != "shared-name" {
		t.Fatalf("occupant was reused or rewritten: %+v", got)
	}

	if _, err := repo.Get(ctx, "prescribed"); !errors.Is(err, identity.ErrUserNotFound) {
		t.Fatalf("prescribed party must not exist after username collision, err=%v", err)
	}
}

func TestEnsureParty_EmailCollisionDifferentID(t *testing.T) {
	t.Parallel()

	repo := identity.NewMemoryPartyRepo()
	ctx := t.Context()

	if err := repo.Create(ctx, &identity.User{
		ID:       "occupant",
		Username: "alice",
		Email:    "shared@example.com",
		Role:     identity.RoleUser,
	}); err != nil {
		t.Fatalf("Create occupant: %v", err)
	}

	_, err := identity.EnsureParty(ctx, repo, identity.PartySpec{
		ID:       "prescribed",
		Username: "prescribed-user",
		Email:    "shared@example.com",
		Role:     identity.RoleProbe,
	})
	if !errors.Is(err, identity.ErrEmailExists) {
		t.Fatalf("error = %v, want ErrEmailExists", err)
	}
}

func TestEnsureParty_IncompatibleExistingID(t *testing.T) {
	t.Parallel()

	repo := identity.NewMemoryPartyRepo()
	ctx := t.Context()

	if err := repo.Create(ctx, &identity.User{
		ID:       "shared-id",
		Username: "original",
		Role:     identity.RoleUser,
		Realm:    "other.example",
	}); err != nil {
		t.Fatalf("Create original: %v", err)
	}

	_, err := identity.EnsureParty(ctx, repo, identity.PartySpec{
		ID:       "shared-id",
		Username: "replacement",
		Role:     identity.RoleProbe,
		Realm:    "local.example",
	})
	if !errors.Is(err, identity.ErrPartyIdentityMismatch) {
		t.Fatalf("error = %v, want ErrPartyIdentityMismatch", err)
	}
}

func TestEnsureParty_RejectsMissingInputs(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	repo := identity.NewMemoryPartyRepo()

	if _, err := identity.EnsureParty(ctx, nil, identity.PartySpec{ID: "id", Username: "u"}); err == nil {
		t.Fatal("nil repo succeeded")
	}

	if _, err := identity.EnsureParty(ctx, repo, identity.PartySpec{Username: "u"}); err == nil {
		t.Fatal("empty id succeeded")
	}

	if _, err := identity.EnsureParty(ctx, repo, identity.PartySpec{ID: "id"}); err == nil {
		t.Fatal("empty username succeeded")
	}
}

func TestEnsureParty_ConcurrentSameSpec(t *testing.T) {
	t.Parallel()

	repo := identity.NewMemoryPartyRepo()
	ctx := t.Context()
	spec := identity.PartySpec{
		ID:       "race-id",
		Username: "race-user",
		Role:     identity.RoleProbe,
		Realm:    "local.example",
	}

	const workers = 8

	start := make(chan struct{})
	errs := make([]error, workers)
	ids := make([]string, workers)

	var wg sync.WaitGroup

	wg.Add(workers)

	for i := range workers {
		go func() {
			defer wg.Done()

			<-start

			user, err := identity.EnsureParty(ctx, repo, spec)
			errs[i] = err

			if err == nil {
				ids[i] = user.ID
			}
		}()
	}

	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("worker %d: %v", i, err)
		}

		if ids[i] != spec.ID {
			t.Fatalf("worker %d id = %q, want %q", i, ids[i], spec.ID)
		}
	}

	users, err := repo.List(ctx, "")
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	if len(users) != 1 {
		t.Fatalf("users = %d, want 1", len(users))
	}
}

func TestEnsureParty_ConcurrentUsernameCollision(t *testing.T) {
	t.Parallel()

	repo := identity.NewMemoryPartyRepo()
	ctx := t.Context()
	start := make(chan struct{})
	errs := make(chan error, 2)

	var wg sync.WaitGroup

	wg.Add(2)

	go func() {
		defer wg.Done()

		<-start

		_, err := identity.EnsureParty(ctx, repo, identity.PartySpec{
			ID:       "id-a",
			Username: "shared-race",
			Role:     identity.RoleProbe,
		})
		errs <- err
	}()

	go func() {
		defer wg.Done()

		<-start

		_, err := identity.EnsureParty(ctx, repo, identity.PartySpec{
			ID:       "id-b",
			Username: "shared-race",
			Role:     identity.RoleProbe,
		})
		errs <- err
	}()

	close(start)
	wg.Wait()
	close(errs)

	var won, collided int

	for err := range errs {
		switch {
		case err == nil:
			won++
		case errors.Is(err, identity.ErrUserExists):
			collided++
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}

	if won != 1 || collided != 1 {
		t.Fatalf("won=%d collided=%d, want 1 and 1", won, collided)
	}
}

func TestEnsureSessionInviter_UsesTestRunID(t *testing.T) {
	t.Parallel()

	repo := identity.NewMemoryPartyRepo()
	ctx := t.Context()
	testRunID := "01900000-0000-7000-8000-0000000000a1"

	user, err := identity.EnsureSessionInviter(ctx, repo, testRunID, "local.example")
	if err != nil {
		t.Fatalf("EnsureSessionInviter: %v", err)
	}

	if user.ID != testRunID {
		t.Fatalf("id = %q, want test run id", user.ID)
	}

	if user.Username != "session-inviter-"+testRunID {
		t.Fatalf("username = %q", user.Username)
	}

	if user.DisplayName != "Session Inviter" {
		t.Fatalf("display name = %q", user.DisplayName)
	}

	if user.Role != identity.RoleProbe || user.Realm != "local.example" || user.ExpiresAt != nil {
		t.Fatalf("inviter party = %+v", user)
	}

	again, err := identity.EnsureSessionInviter(ctx, repo, testRunID, "local.example")
	if err != nil {
		t.Fatalf("EnsureSessionInviter reuse: %v", err)
	}

	if again.ID != user.ID {
		t.Fatalf("reused id = %q, want %q", again.ID, user.ID)
	}
}

func TestEnsureReverseReceiver_UsesBobUserIDAndProbeIdentity(t *testing.T) {
	t.Parallel()

	repo := identity.NewMemoryPartyRepo()
	ctx := t.Context()
	bobID := "01900000-0000-7000-8000-0000000000b1"

	user, err := identity.EnsureReverseReceiver(ctx, repo, identity.ReverseReceiverSpec{
		ID:          bobID,
		Email:       config.DefaultValidatorProbeEmail,
		DisplayName: config.DefaultValidatorProbeDisplayName,
		Realm:       "local.example",
	})
	if err != nil {
		t.Fatalf("EnsureReverseReceiver: %v", err)
	}

	if user.ID != bobID {
		t.Fatalf("id = %q, want bob user id", user.ID)
	}

	if user.Username != "session-receiver-"+bobID {
		t.Fatalf("username = %q", user.Username)
	}

	wantEmail := "probe+" + bobID + "@localhost"
	if user.Email != wantEmail {
		t.Fatalf("email = %q, want %q", user.Email, wantEmail)
	}

	if user.DisplayName != config.DefaultValidatorProbeDisplayName {
		t.Fatalf("display name = %q", user.DisplayName)
	}

	if user.Role != identity.RoleProbe || user.ExpiresAt != nil {
		t.Fatalf("receiver party = %+v", user)
	}

	other, err := identity.EnsureReverseReceiver(ctx, repo, identity.ReverseReceiverSpec{
		ID:          "01900000-0000-7000-8000-0000000000b2",
		Email:       config.DefaultValidatorProbeEmail,
		DisplayName: config.DefaultValidatorProbeDisplayName,
		Realm:       "local.example",
	})
	if err != nil {
		t.Fatalf("second receiver: %v", err)
	}

	if other.ID == user.ID || other.Email == user.Email {
		t.Fatal("second receiver reused the first party")
	}
}

func TestEnsureReverseReceiver_RequiresID(t *testing.T) {
	t.Parallel()

	_, err := identity.EnsureReverseReceiver(t.Context(), identity.NewMemoryPartyRepo(), identity.ReverseReceiverSpec{
		Email: config.DefaultValidatorProbeEmail,
	})
	if err == nil {
		t.Fatal("empty receiver id succeeded")
	}
}

func TestEnsureSessionInviter_RequiresID(t *testing.T) {
	t.Parallel()

	if _, err := identity.EnsureSessionInviter(t.Context(), identity.NewMemoryPartyRepo(), "", "local.example"); err == nil {
		t.Fatal("empty inviter id succeeded")
	}
}
