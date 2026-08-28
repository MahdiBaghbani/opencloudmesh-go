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
)

func TestMemoryPartyRepo_DuplicateID_NonProbeCollision(t *testing.T) {
	t.Parallel()

	repo := identity.NewMemoryPartyRepo()
	ctx := t.Context()

	const sharedID = "01900000-0000-7000-8000-0000000000a1"

	user := &identity.User{
		ID:       sharedID,
		Username: "alice",
		Role:     identity.RoleUser,
	}
	if err := repo.Create(ctx, user); err != nil {
		t.Fatalf("Create user: %v", err)
	}

	probe := &identity.User{
		ID:       sharedID,
		Username: "probe-collide",
		Role:     identity.RoleProbe,
	}

	err := repo.Create(ctx, probe)
	if !errors.Is(err, identity.ErrUserIDExists) {
		t.Fatalf("error = %v, want ErrUserIDExists for non-probe ID collision", err)
	}

	got, err := repo.Get(ctx, sharedID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	if got.Username != "alice" || got.IsProbe() {
		t.Fatalf("non-probe party was overwritten: username=%q role=%q", got.Username, got.Role)
	}
}

func TestMemoryPartyRepo_DuplicateIDConcurrent(t *testing.T) {
	t.Parallel()

	repo := identity.NewMemoryPartyRepo()
	ctx := t.Context()

	const sharedID = "01900000-0000-7000-8000-0000000000c1"

	start := make(chan struct{})
	errs := make(chan error, 2)

	var wg sync.WaitGroup

	wg.Add(2)

	go func() {
		defer wg.Done()

		<-start

		errs <- repo.Create(ctx, &identity.User{
			ID:       sharedID,
			Username: "alice-race",
			Role:     identity.RoleUser,
		})
	}()

	go func() {
		defer wg.Done()

		<-start

		errs <- repo.Create(ctx, &identity.User{
			ID:       sharedID,
			Username: "bob-race",
			Role:     identity.RoleUser,
		})
	}()

	close(start)
	wg.Wait()
	close(errs)

	var won, dup int

	for err := range errs {
		switch {
		case err == nil:
			won++
		case errors.Is(err, identity.ErrUserIDExists):
			dup++
		default:
			t.Fatalf("unexpected create error: %v", err)
		}
	}

	if won != 1 || dup != 1 {
		t.Fatalf("concurrent duplicate ID: won=%d dup=%d, want 1 and 1", won, dup)
	}

	got, err := repo.Get(ctx, sharedID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	if got.ID != sharedID {
		t.Fatalf("stored ID = %q, want %q", got.ID, sharedID)
	}
}
