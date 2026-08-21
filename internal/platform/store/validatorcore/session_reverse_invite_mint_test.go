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

func seedReverseInviteRun(t *testing.T, core *Core, runID, state string) {
	t.Helper()

	now := time.Now().Unix()

	if err := core.DB().WithContext(t.Context()).Create(&TestRun{
		TestRunID:      runID,
		IsActive:       true,
		State:          state,
		TargetOrigin:   "https://peer.example",
		TargetHost:     "peer.example",
		DiscoveryURL:   "https://peer.example/.well-known/ocm",
		ManifestSchema: "ocm-validator-manifest/v1",
		CreatedAt:      now,
		UpdatedAt:      now,
	}).Error; err != nil {
		t.Fatalf("seed active run %s: %v", runID, err)
	}
}

func countCorrelations(t *testing.T, core *Core, runID, role string) int {
	t.Helper()

	var count int64
	if err := core.DB().WithContext(t.Context()).
		Model(&ShareCorrelation{}).
		Where("test_run_id = ? AND role = ?", runID, role).
		Count(&count).Error; err != nil {
		t.Fatalf("count correlations: %v", err)
	}

	return int(count)
}

func TestMintOutgoingInviteBinding_BindsSlotAndAdvancesState(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-mint-basic"

	seedReverseInviteRun(t, core, runID, StateActiveRunning)

	if err := core.MintOutgoingInviteBinding(ctx, runID, "invite-1", "token-1"); err != nil {
		t.Fatalf("mint: %v", err)
	}

	run, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if run.State != StateInviteMinted {
		t.Fatalf("state = %q, want %q", run.State, StateInviteMinted)
	}

	if run.OutgoingInviteID == nil || *run.OutgoingInviteID != "invite-1" {
		t.Fatalf("outgoing_invite_id = %v, want invite-1", run.OutgoingInviteID)
	}

	if got := countCorrelations(t, core, runID, RoleOutgoingInvite); got != 0 {
		t.Fatalf("outgoing invite correlation rows = %d, want 0", got)
	}
}

func TestMintOutgoingInviteBinding_IdempotentSameIDAndToken(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-mint-idem"

	seedReverseInviteRun(t, core, runID, StateActiveRunning)

	for range 3 {
		if err := core.MintOutgoingInviteBinding(ctx, runID, "invite-1", "token-1"); err != nil {
			t.Fatalf("mint retry: %v", err)
		}
	}

	if got := countCorrelations(t, core, runID, RoleOutgoingInvite); got != 0 {
		t.Fatalf("outgoing invite correlation rows = %d, want 0", got)
	}

	run, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if run.State != StateInviteMinted {
		t.Fatalf("state = %q, want %q", run.State, StateInviteMinted)
	}

	if run.OutgoingInviteID == nil || *run.OutgoingInviteID != "invite-1" {
		t.Fatalf("outgoing_invite_id = %v, want invite-1", run.OutgoingInviteID)
	}
}

func TestMintOutgoingInviteBinding_SameIDDifferentTokenIsIdempotent(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-mint-same-id-token"

	seedReverseInviteRun(t, core, runID, StateActiveRunning)

	if err := core.MintOutgoingInviteBinding(ctx, runID, "invite-1", "token-1"); err != nil {
		t.Fatalf("mint: %v", err)
	}

	if err := core.MintOutgoingInviteBinding(ctx, runID, "invite-1", "token-other"); err != nil {
		t.Fatalf("mint same id different token = %v, want idempotent success", err)
	}

	run, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if run.OutgoingInviteID == nil || *run.OutgoingInviteID != "invite-1" {
		t.Fatalf("outgoing_invite_id = %v, want invite-1", run.OutgoingInviteID)
	}
}

func TestMintOutgoingInviteBinding_ConflictOnDifferentInviteID(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-mint-conflict-id"

	seedReverseInviteRun(t, core, runID, StateActiveRunning)

	if err := core.MintOutgoingInviteBinding(ctx, runID, "invite-1", "token-1"); err != nil {
		t.Fatalf("mint: %v", err)
	}

	err := core.MintOutgoingInviteBinding(ctx, runID, "invite-2", "token-1")
	if !errors.Is(err, ErrShareCorrelationConflict) {
		t.Fatalf("mint different invite id = %v, want ErrShareCorrelationConflict", err)
	}
}

func TestMintOutgoingInviteBinding_MissOutsideActiveRunning(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-mint-wrong-state"

	seedReverseInviteRun(t, core, runID, StateInviteAccepted)

	err := core.MintOutgoingInviteBinding(ctx, runID, "invite-1", "token-1")
	if !errors.Is(err, ErrStateTransitionMiss) {
		t.Fatalf("mint = %v, want ErrStateTransitionMiss", err)
	}

	if got := countCorrelations(t, core, runID, RoleOutgoingInvite); got != 0 {
		t.Fatalf("outgoing invite correlation rows = %d, want 0", got)
	}

	runAfterMiss, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun after miss: %v", err)
	}

	if runAfterMiss.OutgoingInviteID != nil {
		t.Fatalf("outgoing_invite_id = %v, want nil after miss", runAfterMiss.OutgoingInviteID)
	}

	run, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if run.State != StateInviteAccepted {
		t.Fatalf("state = %q, want %q (unchanged)", run.State, StateInviteAccepted)
	}
}

func TestMintOutgoingInviteBinding_CrossRunInviteIDIsStoreError(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
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

	err := core.MintOutgoingInviteBinding(ctx, challengerID, inviteID, "token-challenger")

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

func TestMintOutgoingInviteBinding_SessionNotFound(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)

	err := core.MintOutgoingInviteBinding(t.Context(), "run-missing", "invite-1", "token-1")
	if !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("mint = %v, want ErrSessionNotFound", err)
	}
}

func TestMintOutgoingInviteBinding_ConcurrentSingleWinner(t *testing.T) {
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

			errs[i] = core.MintOutgoingInviteBinding(ctx, runID, fmt.Sprintf("invite-%d", i), fmt.Sprintf("token-%d", i))
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

	if got := countCorrelations(t, core, runID, RoleOutgoingInvite); got != 0 {
		t.Fatalf("outgoing invite correlation rows = %d, want 0", got)
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

	if got := countCorrelations(t, core, runID, RoleIncomingInvite); got != 1 {
		t.Fatalf("correlation rows = %d, want 1", got)
	}

	requireState(t, core, runID, StateReverseInviteAccepted)
}

func TestGetShareCorrelation_ExactlyOneRow(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-corr-find"

	seedReverseInviteRun(t, core, runID, StateActiveRunning)

	if _, err := core.GetShareCorrelation(ctx, runID, RoleOutgoingInvite, LocalIdentityA); !errors.Is(err, ErrShareCorrelationNotFound) {
		t.Fatalf("missing row = %v, want ErrShareCorrelationNotFound", err)
	}

	if _, err := core.GetShareCorrelation(ctx, runID, RoleOutgoingInvite, ""); !errors.Is(err, ErrInvalidLocalIdentity) {
		t.Fatalf("empty local identity = %v, want ErrInvalidLocalIdentity", err)
	}

	if _, err := core.GetShareCorrelation(ctx, runID, RoleOutgoingInvite, "c"); !errors.Is(err, ErrInvalidLocalIdentity) {
		t.Fatalf("unknown local identity = %v, want ErrInvalidLocalIdentity", err)
	}

	if err := core.MintOutgoingInviteBinding(ctx, runID, "invite-1", "token-1"); err != nil {
		t.Fatalf("mint: %v", err)
	}

	if _, err := core.GetShareCorrelation(ctx, runID, RoleOutgoingInvite, LocalIdentityA); !errors.Is(err, ErrShareCorrelationNotFound) {
		t.Fatalf("minted run outgoing correlation = %v, want ErrShareCorrelationNotFound", err)
	}

	manual := ShareCorrelation{
		TestRunID:     runID,
		Role:          RoleOutgoingInvite,
		LocalIdentity: LocalIdentityA,
		SenderHost:    "peer.example",
		ProviderID:    "token-1",
		Status:        CorrelationStatusConfirmed,
		CreatedAt:     time.Now().Unix(),
	}
	if err := core.DB().WithContext(ctx).Create(&manual).Error; err != nil {
		t.Fatalf("manual outgoing_invite insert: %v", err)
	}

	if _, err := core.GetShareCorrelation(ctx, runID, RoleOutgoingInvite, LocalIdentityA); err != nil {
		t.Fatalf("get: %v", err)
	}

	// The outgoing invite slot unique is gone; a second outgoing_invite
	// row with a distinct composite is accepted.
	dup := ShareCorrelation{
		TestRunID:     runID,
		Role:          RoleOutgoingInvite,
		LocalIdentity: LocalIdentityB,
		SenderHost:    "peer.example",
		ProviderID:    "token-dup",
		Status:        CorrelationStatusConfirmed,
		CreatedAt:     time.Now().Unix(),
	}
	if err := core.DB().WithContext(ctx).Create(&dup).Error; err != nil {
		t.Fatalf("second outgoing_invite row must be accepted: %v", err)
	}
}
