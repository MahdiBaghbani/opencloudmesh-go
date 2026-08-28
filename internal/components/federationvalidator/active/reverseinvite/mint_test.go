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
	env.requireNoS1Claim(t, runID)

	if all[0].Token != first.Token {
		t.Fatalf("stored token changed on retry")
	}
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
	// canonical invite, whether it won the binding race or recovered
	// the already-bound invite by pointer without reminting.
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

	run, err := env.store.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if run.OutgoingInviteID == nil || *run.OutgoingInviteID != canonical {
		t.Fatalf("outgoing_invite_id = %v, want %q", run.OutgoingInviteID, canonical)
	}

	env.requireState(t, runID, validatorcore.StateInviteMinted)
	env.requireNoS1Claim(t, runID)
}

func TestMintOutgoingInvite_RetryAfterClaimDoesNotRearm(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	ctx := t.Context()
	runID := "run-mint-no-rearm"

	env.seedRun(t, runID, validatorcore.StateActiveRunning)

	first, err := env.svc.MintOutgoingInvite(ctx, runID)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	if _, claimErr := env.store.ClaimOutgoingInvite(ctx, runID); claimErr != nil {
		t.Fatalf("claim: %v", claimErr)
	}

	claimed, loadErr := env.store.GetTestRun(ctx, runID)
	if loadErr != nil {
		t.Fatalf("GetTestRun after claim: %v", loadErr)
	}

	if claimed.S1ClaimedAt == nil {
		t.Fatal("s1_claimed_at is nil after claim")
	}

	claimedAt := *claimed.S1ClaimedAt

	again, err := env.svc.MintOutgoingInvite(ctx, runID)
	if err != nil {
		t.Fatalf("mint retry: %v", err)
	}

	if again.ID != first.ID || again.Token != first.Token {
		t.Fatalf("retry reminted %q/%q, want %q/%q", again.ID, again.Token, first.ID, first.Token)
	}

	after, err := env.store.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun after retry: %v", err)
	}

	if after.S1ClaimedAt == nil || *after.S1ClaimedAt != claimedAt {
		t.Fatalf("s1_claimed_at = %v, want %d", after.S1ClaimedAt, claimedAt)
	}

	all, err := env.outgoing.List(ctx)
	if err != nil {
		t.Fatalf("list outgoing: %v", err)
	}

	if len(all) != 1 {
		t.Fatalf("outgoing invites = %d, want 1", len(all))
	}
}

func TestMintOutgoingInvite_RequiresActiveRun(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	ctx := t.Context()
	runID := "run-mint-inactive"

	if err := env.store.DB().WithContext(ctx).Create(&validatorcore.TestRun{
		TestRunID:  runID,
		IsActive:   false,
		State:      validatorcore.StateCreated,
		TargetHost: testTargetHost,
		CreatedAt:  1,
		UpdatedAt:  1,
	}).Error; err != nil {
		t.Fatalf("seed passive run: %v", err)
	}

	_, err := env.svc.MintOutgoingInvite(ctx, runID)
	if !errors.Is(err, reverseinvite.ErrSessionNotActive) {
		t.Fatalf("mint = %v, want ErrSessionNotActive", err)
	}
}
