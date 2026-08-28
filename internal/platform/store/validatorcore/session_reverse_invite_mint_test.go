// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"errors"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
)

func TestMintOutgoingInvite_BindsSlotAndAdvancesState(t *testing.T) {
	t.Parallel()

	core := openMigratedProductionCore(t)
	ctx := t.Context()
	runID := "run-mint-basic"

	seedReverseInviteRun(t, core, runID, StateActiveRunning)

	if err := core.MintOutgoingInvite(ctx, runID, sampleOutgoingMint("invite-1", "token-1", runID)); err != nil {
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

	if got := countShareCorrelations(t, core, runID); got != 0 {
		t.Fatalf("share correlation rows = %d, want 0", got)
	}

	if got := countOutgoingInvites(t, core); got != 1 {
		t.Fatalf("outgoing invites = %d, want 1", got)
	}

	requireNoS1Claim(t, core, runID)
}

func TestMintOutgoingInvite_IdempotentSameIDAndToken(t *testing.T) {
	t.Parallel()

	core := openMigratedProductionCore(t)
	ctx := t.Context()
	runID := "run-mint-idem"

	seedReverseInviteRun(t, core, runID, StateActiveRunning)

	for range 3 {
		if err := core.MintOutgoingInvite(ctx, runID, sampleOutgoingMint("invite-1", "token-1", runID)); err != nil {
			t.Fatalf("mint retry: %v", err)
		}
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

	if run.OutgoingInviteID == nil || *run.OutgoingInviteID != "invite-1" {
		t.Fatalf("outgoing_invite_id = %v, want invite-1", run.OutgoingInviteID)
	}

	if got := countOutgoingInvites(t, core); got != 1 {
		t.Fatalf("outgoing invites = %d, want 1", got)
	}

	requireNoS1Claim(t, core, runID)
}

func TestMintOutgoingInvite_SameIDDifferentTokenIsIdempotent(t *testing.T) {
	t.Parallel()

	core := openMigratedProductionCore(t)
	ctx := t.Context()
	runID := "run-mint-same-id-token"

	seedReverseInviteRun(t, core, runID, StateActiveRunning)

	if err := core.MintOutgoingInvite(ctx, runID, sampleOutgoingMint("invite-1", "token-1", runID)); err != nil {
		t.Fatalf("mint: %v", err)
	}

	if err := core.MintOutgoingInvite(ctx, runID, sampleOutgoingMint("invite-1", "token-other", runID)); err != nil {
		t.Fatalf("mint same id different token = %v, want idempotent success", err)
	}

	run, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if run.OutgoingInviteID == nil || *run.OutgoingInviteID != "invite-1" {
		t.Fatalf("outgoing_invite_id = %v, want invite-1", run.OutgoingInviteID)
	}

	var stored store.OutgoingInvite
	if err := core.DB().WithContext(ctx).First(&stored, "id = ?", "invite-1").Error; err != nil {
		t.Fatalf("load product invite: %v", err)
	}

	if stored.Token != "token-1" {
		t.Fatalf("stored token = %q, want original token-1", stored.Token)
	}

	if got := countOutgoingInvites(t, core); got != 1 {
		t.Fatalf("outgoing invites = %d, want 1", got)
	}

	requireNoS1Claim(t, core, runID)
}

func TestMintOutgoingInvite_ConflictOnDifferentInviteID(t *testing.T) {
	t.Parallel()

	core := openMigratedProductionCore(t)
	ctx := t.Context()
	runID := "run-mint-conflict-id"

	seedReverseInviteRun(t, core, runID, StateActiveRunning)

	if err := core.MintOutgoingInvite(ctx, runID, sampleOutgoingMint("invite-1", "token-1", runID)); err != nil {
		t.Fatalf("mint: %v", err)
	}

	err := core.MintOutgoingInvite(ctx, runID, sampleOutgoingMint("invite-2", "token-2", runID))
	if !errors.Is(err, ErrShareCorrelationConflict) {
		t.Fatalf("mint different invite id = %v, want ErrShareCorrelationConflict", err)
	}

	if got := countOutgoingInvites(t, core); got != 1 {
		t.Fatalf("outgoing invites = %d, want 1", got)
	}
}

func TestMintOutgoingInvite_MissOutsideActiveRunning(t *testing.T) {
	t.Parallel()

	core := openMigratedProductionCore(t)
	ctx := t.Context()
	runID := "run-mint-wrong-state"

	seedReverseInviteRun(t, core, runID, StateInviteAccepted)

	err := core.MintOutgoingInvite(ctx, runID, sampleOutgoingMint("invite-1", "token-1", runID))
	if !errors.Is(err, ErrStateTransitionMiss) {
		t.Fatalf("mint = %v, want ErrStateTransitionMiss", err)
	}

	if got := countShareCorrelations(t, core, runID); got != 0 {
		t.Fatalf("share correlation rows = %d, want 0", got)
	}

	if got := countOutgoingInvites(t, core); got != 0 {
		t.Fatalf("outgoing invites after miss = %d, want 0", got)
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

func TestMintOutgoingInvite_SessionNotFound(t *testing.T) {
	t.Parallel()

	core := openMigratedProductionCore(t)

	err := core.MintOutgoingInvite(t.Context(), "run-missing", sampleOutgoingMint("invite-1", "token-1", "run-missing"))
	if !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("mint = %v, want ErrSessionNotFound", err)
	}
}
