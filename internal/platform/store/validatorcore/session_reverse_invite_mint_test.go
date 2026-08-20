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
)

func seedReverseInviteRun(t *testing.T, core *Core, runID, state string) {
	t.Helper()

	now := time.Now().Unix()

	if err := core.DB().WithContext(t.Context()).Create(&TestRun{
		TestRunID:   runID,
		IsActive:    true,
		State:       state,
		SessionKind: SessionKindActiveFull,
		TargetHost:  "peer.example",
		CreatedAt:   now,
		UpdatedAt:   now,
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

	corr, err := core.GetShareCorrelation(ctx, runID, RoleOutgoingInvite, LocalIdentityA)
	if err != nil {
		t.Fatalf("GetShareCorrelation: %v", err)
	}

	if corr.InviteID == nil || *corr.InviteID != "invite-1" {
		t.Fatalf("invite id = %v, want invite-1", corr.InviteID)
	}

	if corr.ProviderID != "token-1" {
		t.Fatalf("provider id = %q, want token-1", corr.ProviderID)
	}

	if corr.SenderHost != "peer.example" {
		t.Fatalf("sender host = %q, want peer.example", corr.SenderHost)
	}

	if corr.Status != CorrelationStatusConfirmed {
		t.Fatalf("status = %q, want %q", corr.Status, CorrelationStatusConfirmed)
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

	if got := countCorrelations(t, core, runID, RoleOutgoingInvite); got != 1 {
		t.Fatalf("correlation rows = %d, want 1", got)
	}

	run, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if run.State != StateInviteMinted {
		t.Fatalf("state = %q, want %q", run.State, StateInviteMinted)
	}
}

func TestMintOutgoingInviteBinding_ConflictOnDifferentToken(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-mint-conflict-token"

	seedReverseInviteRun(t, core, runID, StateActiveRunning)

	if err := core.MintOutgoingInviteBinding(ctx, runID, "invite-1", "token-1"); err != nil {
		t.Fatalf("mint: %v", err)
	}

	err := core.MintOutgoingInviteBinding(ctx, runID, "invite-1", "token-other")
	if !errors.Is(err, ErrShareCorrelationConflict) {
		t.Fatalf("mint different token = %v, want ErrShareCorrelationConflict", err)
	}

	if got := countCorrelations(t, core, runID, RoleOutgoingInvite); got != 1 {
		t.Fatalf("correlation rows = %d, want 1", got)
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
		t.Fatalf("correlation rows = %d, want 0 (rolled back)", got)
	}

	run, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if run.State != StateInviteAccepted {
		t.Fatalf("state = %q, want %q (unchanged)", run.State, StateInviteAccepted)
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

	if got := countCorrelations(t, core, runID, RoleOutgoingInvite); got != 1 {
		t.Fatalf("correlation rows = %d, want 1", got)
	}

	run, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if run.State != StateInviteMinted {
		t.Fatalf("state = %q, want %q", run.State, StateInviteMinted)
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

	requireState(t, core, runID, StateReverseInviteImported)
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

	if _, err := core.GetShareCorrelation(ctx, runID, RoleOutgoingInvite, LocalIdentityA); err != nil {
		t.Fatalf("get: %v", err)
	}

	// The role slot is one row per run; a second outgoing_invite row for the
	// same run is rejected by the partial unique index.
	dup := ShareCorrelation{
		TestRunID:     runID,
		Role:          RoleOutgoingInvite,
		LocalIdentity: LocalIdentityB,
		SenderHost:    "peer.example",
		ProviderID:    "token-dup",
		Status:        CorrelationStatusConfirmed,
		CreatedAt:     time.Now().Unix(),
	}
	if err := core.DB().WithContext(ctx).Create(&dup).Error; err == nil {
		t.Fatal("duplicate slot row inserted, want unique index rejection")
	}
}
