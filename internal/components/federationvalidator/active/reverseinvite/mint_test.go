// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package reverseinvite_test

import (
	"errors"
	"sync"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/active/reverseinvite"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

func TestMintOutgoingInvite_OneCanonicalInvitePerRun(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	ctx := t.Context()
	runID := "run-mint-canonical"

	env.seedRun(t, runID, validatorcore.StateActiveRunning)

	first, err := env.svc.MintOutgoingInvite(ctx, runID)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	if first.CreatedByUserID != runID {
		t.Fatalf("created_by = %q, want run id", first.CreatedByUserID)
	}

	if first.Status != invites.InviteStatusPending {
		t.Fatalf("status = %q, want pending", first.Status)
	}

	// The inviting party exists so the product handler can build its identity
	// response for this invite.
	if _, getErr := env.parties.Get(ctx, runID); getErr != nil {
		t.Fatalf("session party A missing: %v", getErr)
	}

	second, err := env.svc.MintOutgoingInvite(ctx, runID)
	if err != nil {
		t.Fatalf("mint retry: %v", err)
	}

	if second.ID != first.ID || second.Token != first.Token {
		t.Fatalf("retry returned %q/%q, want canonical %q/%q", second.ID, second.Token, first.ID, first.Token)
	}

	all, err := env.outgoing.List(ctx)
	if err != nil {
		t.Fatalf("list outgoing: %v", err)
	}

	if len(all) != 1 {
		t.Fatalf("outgoing invites = %d, want 1", len(all))
	}

	env.requireState(t, runID, validatorcore.StateInviteMinted)
}

func TestMintOutgoingInvite_ConcurrentCreatesRaceToOneWinner(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	ctx := t.Context()
	runID := "run-mint-race"

	env.seedRun(t, runID, validatorcore.StateActiveRunning)

	const workers = 8

	var wg sync.WaitGroup

	ids := make([]string, workers)
	errs := make([]error, workers)

	for i := range workers {
		wg.Add(1)

		go func() {
			defer wg.Done()

			invite, err := env.svc.MintOutgoingInvite(ctx, runID)
			if err == nil {
				ids[i] = invite.ID
			}

			errs[i] = err
		}()
	}

	wg.Wait()

	// No worker error is swallowed: every caller must observe the one
	// canonical invite, whether it won the binding race or healed it.
	for i, err := range errs {
		if err != nil {
			t.Errorf("worker %d failed: %v", i, err)
		}
	}

	if t.Failed() {
		t.FailNow()
	}

	canonical := ids[0]
	for i, id := range ids {
		if id != canonical {
			t.Fatalf("worker %d saw invite %q, want canonical %q", i, id, canonical)
		}
	}

	all, err := env.outgoing.List(ctx)
	if err != nil {
		t.Fatalf("list outgoing: %v", err)
	}

	if len(all) != 1 {
		t.Fatalf("outgoing invites = %d, want 1", len(all))
	}

	if all[0].ID != canonical {
		t.Fatalf("stored invite = %q, want canonical %q", all[0].ID, canonical)
	}

	var corrCount int64
	if err := env.store.DB().WithContext(ctx).
		Model(&validatorcore.ShareCorrelation{}).
		Where("test_run_id = ? AND role = ?", runID, validatorcore.RoleOutgoingInvite).
		Count(&corrCount).Error; err != nil {
		t.Fatalf("count correlations: %v", err)
	}

	if corrCount != 1 {
		t.Fatalf("correlation rows = %d, want 1", corrCount)
	}

	env.requireState(t, runID, validatorcore.StateInviteMinted)
}

func TestMintOutgoingInvite_CreateFailureHealsOnRetry(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	ctx := t.Context()
	runID := "run-mint-heal"

	env.seedRun(t, runID, validatorcore.StateActiveRunning)

	// First mint wins the binding but crashes before the product invite
	// create commits: the run is left in invite_minted with no invite row.
	flaky := &failOnceOutgoingRepo{inner: env.outgoing}
	flaky.failCreate.Store(true)

	crashingSvc, newErr := reverseinvite.New(reverseinvite.Deps{
		Store:           env.store,
		OutgoingInvites: flaky,
		IncomingInvites: env.incoming,
		Parties:         env.parties,
		Poster:          env.poster,
		LocalIdentity:   testLocalIdentity(),
	})
	if newErr != nil {
		t.Fatalf("reverseinvite.New: %v", newErr)
	}

	if _, err := crashingSvc.MintOutgoingInvite(ctx, runID); err == nil {
		t.Fatal("mint with failing create succeeded, want injected failure")
	}

	env.requireState(t, runID, validatorcore.StateInviteMinted)

	if all, listErr := env.outgoing.List(ctx); listErr != nil {
		t.Fatalf("list outgoing: %v", listErr)
	} else if len(all) != 0 {
		t.Fatalf("outgoing invites after crash = %d, want 0", len(all))
	}

	// The retry must heal the bound-but-missing slot: same bound invite id
	// and token, exactly one stored row.
	healed, err := env.svc.MintOutgoingInvite(ctx, runID)
	if err != nil {
		t.Fatalf("mint retry: %v", err)
	}

	corr, err := env.store.GetShareCorrelation(ctx, runID, validatorcore.RoleOutgoingInvite, validatorcore.LocalIdentityA)
	if err != nil {
		t.Fatalf("GetShareCorrelation: %v", err)
	}

	if corr.InviteID == nil || *corr.InviteID != healed.ID {
		t.Fatalf("healed invite id = %q, want bound %v", healed.ID, corr.InviteID)
	}

	if healed.Token != corr.ProviderID {
		t.Fatalf("healed token = %q, want bound %q", healed.Token, corr.ProviderID)
	}

	all, err := env.outgoing.List(ctx)
	if err != nil {
		t.Fatalf("list outgoing: %v", err)
	}

	if len(all) != 1 {
		t.Fatalf("outgoing invites = %d, want 1", len(all))
	}

	// A third caller observes the healed canonical invite.
	again, err := env.svc.MintOutgoingInvite(ctx, runID)
	if err != nil {
		t.Fatalf("mint after heal: %v", err)
	}

	if again.ID != healed.ID || again.Token != healed.Token {
		t.Fatalf("post-heal mint = %q/%q, want canonical %q/%q", again.ID, again.Token, healed.ID, healed.Token)
	}

	env.requireState(t, runID, validatorcore.StateInviteMinted)
}

func TestMintOutgoingInvite_RequiresActiveRun(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	ctx := t.Context()
	runID := "run-mint-inactive"

	if err := env.store.DB().WithContext(ctx).Create(&validatorcore.TestRun{
		TestRunID:   runID,
		IsActive:    false,
		State:       validatorcore.StateCreated,
		SessionKind: validatorcore.SessionKindPassiveOnly,
		TargetHost:  testTargetHost,
		CreatedAt:   1,
		UpdatedAt:   1,
	}).Error; err != nil {
		t.Fatalf("seed passive run: %v", err)
	}

	_, err := env.svc.MintOutgoingInvite(ctx, runID)
	if !errors.Is(err, reverseinvite.ErrSessionNotActive) {
		t.Fatalf("mint = %v, want ErrSessionNotActive", err)
	}
}
