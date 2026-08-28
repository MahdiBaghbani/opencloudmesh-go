// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"gorm.io/gorm"
)

func TestMintOutgoingInvite_CrossRunInviteIDIsStoreError(t *testing.T) {
	t.Parallel()

	core := openMigratedProductionCore(t)
	ctx := t.Context()
	now := time.Now().Unix()
	inviteID := "invite-cross-run"
	ownerID := "run-invite-owner"
	challengerID := "run-invite-challenger"

	if err := core.DB().WithContext(ctx).Create(&TestRun{
		TestRunID:        ownerID,
		IsActive:         false,
		State:            StateTerminalPass,
		TargetOrigin:     "https://peer.example",
		TargetHost:       "peer.example",
		DiscoveryURL:     "https://peer.example/.well-known/ocm",
		ManifestSchema:   "ocm-validator-manifest/v1",
		OutgoingInviteID: &inviteID,
		CreatedAt:        now,
		UpdatedAt:        now,
	}).Error; err != nil {
		t.Fatalf("seed owner run: %v", err)
	}

	seedReverseInviteRun(t, core, challengerID, StateActiveRunning)

	err := core.MintOutgoingInvite(ctx, challengerID, sampleOutgoingMint(inviteID, "token-challenger", challengerID))

	var storeErr *StoreError
	if !errors.As(err, &storeErr) || storeErr.Op != OpMintOutgoingInvite {
		t.Fatalf("cross-run mint = %v, want OpMintOutgoingInvite", err)
	}

	if !errors.Is(storeErr.Err, gorm.ErrDuplicatedKey) {
		t.Fatalf("wrapped error = %v, want gorm.ErrDuplicatedKey", storeErr.Err)
	}

	challenger, loadErr := core.GetTestRun(ctx, challengerID)
	if loadErr != nil {
		t.Fatalf("GetTestRun challenger: %v", loadErr)
	}

	if challenger.State != StateActiveRunning {
		t.Fatalf("challenger state = %q, want %q", challenger.State, StateActiveRunning)
	}

	if challenger.OutgoingInviteID != nil {
		t.Fatalf("challenger outgoing_invite_id = %v, want nil", challenger.OutgoingInviteID)
	}

	owner, loadErr := core.GetTestRun(ctx, ownerID)
	if loadErr != nil {
		t.Fatalf("GetTestRun owner: %v", loadErr)
	}

	if owner.OutgoingInviteID == nil || *owner.OutgoingInviteID != inviteID {
		t.Fatalf("owner outgoing_invite_id = %v, want %s", owner.OutgoingInviteID, inviteID)
	}
}

func TestMintOutgoingInvite_ConcurrentSingleWinner(t *testing.T) {
	t.Parallel()

	core := openMigratedProductionCore(t)
	ctx := t.Context()
	runID := "run-mint-race"

	seedReverseInviteRun(t, core, runID, StateActiveRunning)

	const workers = 8

	var wg sync.WaitGroup

	errs := make([]error, workers)

	for i := range workers {
		wg.Add(1)

		go func() {
			defer wg.Done()

			errs[i] = core.MintOutgoingInvite(
				ctx,
				runID,
				sampleOutgoingMint(fmt.Sprintf("invite-%d", i), fmt.Sprintf("token-%d", i), runID),
			)
		}()
	}

	wg.Wait()

	wins := 0

	for _, err := range errs {
		if err == nil {
			wins++

			continue
		}

		if !errors.Is(err, ErrShareCorrelationConflict) {
			t.Fatalf("loser error = %v, want ErrShareCorrelationConflict", err)
		}
	}

	if wins != 1 {
		t.Fatalf("winners = %d, want exactly 1", wins)
	}

	if got := countShareCorrelations(t, core, runID); got != 0 {
		t.Fatalf("share correlation rows = %d, want 0", got)
	}

	run, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if run.State != StateInviteMinted {
		t.Fatalf("state = %q, want %q", run.State, StateInviteMinted)
	}

	if run.OutgoingInviteID == nil || *run.OutgoingInviteID == "" {
		t.Fatal("outgoing_invite_id is empty, want the winning invite id")
	}

	if got := countOutgoingInvites(t, core); got != 1 {
		t.Fatalf("outgoing invites = %d, want 1", got)
	}

	requireNoS1Claim(t, core, runID)
}

func TestMintOutgoingInvite_RetryDoesNotResetClaimedAt(t *testing.T) {
	t.Parallel()

	core := openMigratedProductionCore(t)
	ctx := t.Context()
	runID := "run-mint-no-rearm"

	seedReverseInviteRun(t, core, runID, StateActiveRunning)

	if err := core.MintOutgoingInvite(ctx, runID, sampleOutgoingMint("invite-1", "token-1", runID)); err != nil {
		t.Fatalf("mint: %v", err)
	}

	if _, err := core.ClaimOutgoingInvite(ctx, runID); err != nil {
		t.Fatalf("claim: %v", err)
	}

	claimed, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun after claim: %v", err)
	}

	if claimed.S1ClaimedAt == nil {
		t.Fatal("s1_claimed_at is nil after claim")
	}

	claimedAt := *claimed.S1ClaimedAt

	if retryErr := core.MintOutgoingInvite(ctx, runID, sampleOutgoingMint("invite-1", "token-other", runID)); retryErr != nil {
		t.Fatalf("mint retry after claim: %v", retryErr)
	}

	after, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun after mint retry: %v", err)
	}

	if after.S1ClaimedAt == nil || *after.S1ClaimedAt != claimedAt {
		t.Fatalf("s1_claimed_at = %v, want %d", after.S1ClaimedAt, claimedAt)
	}

	if got := countOutgoingInvites(t, core); got != 1 {
		t.Fatalf("outgoing invites = %d, want 1", got)
	}
}

func TestImportReverseInvite_ConcurrentSingleWinner(t *testing.T) {
	t.Parallel()

	core := openMigratedProductionCore(t)
	ctx := t.Context()
	runID := "run-import-race"

	seedReverseInviteRun(t, core, runID, StateReverseAwaitingInvite)

	const workers = 8

	var wg sync.WaitGroup

	errs := make([]error, workers)

	for i := range workers {
		wg.Add(1)

		go func() {
			defer wg.Done()

			errs[i] = core.ImportReverseInvite(ctx, runID, fmt.Sprintf("token-%d", i), fmt.Sprintf("incoming-%d", i))
		}()
	}

	wg.Wait()

	wins := 0

	for _, err := range errs {
		if err == nil {
			wins++

			continue
		}

		if !errors.Is(err, ErrShareCorrelationConflict) {
			t.Fatalf("loser error = %v, want ErrShareCorrelationConflict", err)
		}
	}

	if wins != 1 {
		t.Fatalf("winners = %d, want exactly 1", wins)
	}

	if got := countIncomingInviteCorrelations(t, core, runID); got != 1 {
		t.Fatalf("correlation rows = %d, want 1", got)
	}

	requireState(t, core, runID, StateReverseInviteAccepted)
}

func TestGetShareCorrelation_ExactlyOneRow(t *testing.T) {
	t.Parallel()

	core := openMigratedProductionCore(t)
	ctx := t.Context()
	runID := "run-corr-find"

	seedReverseInviteRun(t, core, runID, StateActiveRunning)

	if _, err := core.GetShareCorrelation(ctx, runID, RoleOutgoingToTarget, LocalIdentityA); !errors.Is(err, ErrShareCorrelationNotFound) {
		t.Fatalf("missing row = %v, want ErrShareCorrelationNotFound", err)
	}

	if _, err := core.GetShareCorrelation(ctx, runID, RoleOutgoingToTarget, ""); !errors.Is(err, ErrInvalidLocalIdentity) {
		t.Fatalf("empty local identity = %v, want ErrInvalidLocalIdentity", err)
	}

	if _, err := core.GetShareCorrelation(ctx, runID, RoleOutgoingToTarget, "c"); !errors.Is(err, ErrInvalidLocalIdentity) {
		t.Fatalf("unknown local identity = %v, want ErrInvalidLocalIdentity", err)
	}

	if err := core.MintOutgoingInvite(ctx, runID, sampleOutgoingMint("invite-1", "token-1", runID)); err != nil {
		t.Fatalf("mint: %v", err)
	}

	if got := countShareCorrelations(t, core, runID); got != 0 {
		t.Fatalf("mint must not write share_correlation rows, got %d", got)
	}

	if _, err := core.GetShareCorrelation(ctx, runID, RoleOutgoingToTarget, LocalIdentityA); !errors.Is(err, ErrShareCorrelationNotFound) {
		t.Fatalf("minted run share correlation = %v, want ErrShareCorrelationNotFound", err)
	}

	first := ShareCorrelation{
		TestRunID:     runID,
		Role:          RoleOutgoingToTarget,
		LocalIdentity: LocalIdentityA,
		SenderHost:    "peer.example",
		ProviderID:    "share-1",
		Status:        CorrelationStatusConfirmed,
		CreatedAt:     time.Now().Unix(),
	}
	if err := core.DB().WithContext(ctx).Create(&first).Error; err != nil {
		t.Fatalf("insert share-leg row: %v", err)
	}

	if _, err := core.GetShareCorrelation(ctx, runID, RoleOutgoingToTarget, LocalIdentityA); err != nil {
		t.Fatalf("get: %v", err)
	}

	otherIdentity := ShareCorrelation{
		TestRunID:     runID,
		Role:          RoleOutgoingToTarget,
		LocalIdentity: LocalIdentityB,
		SenderHost:    "peer.example",
		ProviderID:    "share-2",
		Status:        CorrelationStatusConfirmed,
		CreatedAt:     time.Now().Unix(),
	}
	if err := core.DB().WithContext(ctx).Create(&otherIdentity).Error; err != nil {
		t.Fatalf("second share-leg row with a distinct composite must be accepted: %v", err)
	}

	sameIdentity := ShareCorrelation{
		TestRunID:     runID,
		Role:          RoleOutgoingToTarget,
		LocalIdentity: LocalIdentityA,
		SenderHost:    "peer.example",
		ProviderID:    "share-3",
		Status:        CorrelationStatusConfirmed,
		CreatedAt:     time.Now().Unix(),
	}
	if err := core.DB().WithContext(ctx).Create(&sameIdentity).Error; err != nil {
		t.Fatalf("same-identity share-leg row with a distinct composite must be accepted: %v", err)
	}

	if _, err := core.GetShareCorrelation(ctx, runID, RoleOutgoingToTarget, LocalIdentityA); !errors.Is(err, ErrShareCorrelationConflict) {
		t.Fatalf("two rows for the same role and identity = %v, want ErrShareCorrelationConflict", err)
	}
}
