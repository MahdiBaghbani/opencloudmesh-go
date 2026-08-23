// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package runner_test

import (
	"testing"
	"time"

	outgoingshares "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api/outgoing/shares"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

func TestDriveOnce_ActiveRunningMintsOneInvite(t *testing.T) {
	t.Parallel()

	env := newRealInviteEnv(t)
	ctx := t.Context()
	runID := "run-drive-mint"

	env.seedActive(t, runID, validatorcore.StateActiveRunning)
	bobID := env.bindBob(t, runID)

	env.runner.DriveOnce(ctx)
	env.requireState(t, runID, validatorcore.StateInviteMinted)

	if _, err := env.parties.Get(ctx, bobID); err != nil {
		t.Fatalf("bob party missing after mint: %v", err)
	}

	if _, err := env.parties.Get(ctx, runID); err != nil {
		t.Fatalf("alice party missing after mint: %v", err)
	}

	run, err := env.store.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if run.OutgoingInviteID == nil || *run.OutgoingInviteID == "" {
		t.Fatal("outgoing_invite_id is empty after mint")
	}

	env.runner.DriveOnce(ctx)
	env.requireState(t, runID, validatorcore.StateInviteMinted)
}

func TestDriveOnce_RestartHealEnsuresBobThenMints(t *testing.T) {
	t.Parallel()

	env := newRealInviteEnv(t)
	ctx := t.Context()
	runID := "run-drive-heal"

	env.seedActive(t, runID, validatorcore.StateActiveRunning)
	bobID := env.bindBob(t, runID)

	if _, err := env.parties.Get(ctx, bobID); err == nil {
		t.Fatal("bob party must be absent before heal")
	}

	env.runner.DriveOnce(ctx)
	env.requireState(t, runID, validatorcore.StateInviteMinted)

	if _, err := env.parties.Get(ctx, bobID); err != nil {
		t.Fatalf("ensure bob on heal: %v", err)
	}
}

func TestDriveOnce_InviteAcceptedAutoSolicits(t *testing.T) {
	t.Parallel()

	env := newRealInviteEnv(t)
	ctx := t.Context()
	runID := "run-drive-solicit"

	env.seedActive(t, runID, validatorcore.StateInviteAccepted)
	env.bindBob(t, runID)

	env.runner.DriveOnce(ctx)
	env.requireState(t, runID, validatorcore.StateReverseAwaitingInvite)

	env.runner.DriveOnce(ctx)
	env.requireState(t, runID, validatorcore.StateReverseAwaitingInvite)
}

func TestDriveOnce_NoopStatesTouchPolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		state     string
		wantTouch bool
	}{
		{
			name:      "invite minted",
			state:     validatorcore.StateInviteMinted,
			wantTouch: true,
		},
		{
			name:      "reverse awaiting invite",
			state:     validatorcore.StateReverseAwaitingInvite,
			wantTouch: true,
		},
		{
			name:      "forward share sent",
			state:     validatorcore.StateForwardShareSent,
			wantTouch: true,
		},
		{
			name:      "capability exercise",
			state:     validatorcore.StateCapabilityExercise,
			wantTouch: false,
		},
		{
			name:      "reverse awaiting share",
			state:     validatorcore.StateReverseAwaitingShare,
			wantTouch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			env := newStubEnv(t, nil, nil)
			runID := "run-noop-" + tt.state
			stale := time.Now().Unix() - 3600

			env.seedActive(t, runID, tt.state)

			if err := env.store.DB().WithContext(t.Context()).Model(&validatorcore.TestRun{}).
				Where("test_run_id = ?", runID).
				Update("updated_at", stale).Error; err != nil {
				t.Fatalf("age updated_at: %v", err)
			}

			env.runner.DriveOnce(t.Context())
			env.requireState(t, runID, tt.state)

			run, err := env.store.GetTestRun(t.Context(), runID)
			if err != nil {
				t.Fatalf("GetTestRun: %v", err)
			}

			if tt.wantTouch {
				if run.UpdatedAt <= stale {
					t.Fatalf("updated_at = %d, want fresher than %d", run.UpdatedAt, stale)
				}
			} else if run.UpdatedAt != stale {
				t.Fatalf("updated_at = %d, want unchanged %d", run.UpdatedAt, stale)
			}

			if env.invites.mints != 0 || env.invites.solicits != 0 || env.out.calls != 0 {
				t.Fatalf("noop drove work: mints=%d solicits=%d creates=%d", env.invites.mints, env.invites.solicits, env.out.calls)
			}
		})
	}
}

func TestDriveOnce_PromotesOldestReadyWaiter(t *testing.T) {
	t.Parallel()

	env := newRealInviteEnv(t)
	ctx := t.Context()
	now := time.Now().Unix()

	seedReadyWaiter(t, env.store, "run-promote-old", now-20)
	seedReadyWaiter(t, env.store, "run-promote-new", now-5)

	env.runner.DriveOnce(ctx)

	old, err := env.store.GetTestRun(ctx, "run-promote-old")
	if err != nil {
		t.Fatalf("GetTestRun old: %v", err)
	}

	if !old.IsActive || old.State != validatorcore.StateActiveRunning {
		t.Fatalf("old waiter is_active=%v state=%q, want active_running", old.IsActive, old.State)
	}

	newer, err := env.store.GetTestRun(ctx, "run-promote-new")
	if err != nil {
		t.Fatalf("GetTestRun new: %v", err)
	}

	if newer.IsActive {
		t.Fatal("newer waiter took the active slot")
	}

	env.runner.DriveOnce(ctx)
	env.requireState(t, "run-promote-old", validatorcore.StateInviteMinted)
}

func TestDriveOnce_BusySlotPromoteIsNoop(t *testing.T) {
	t.Parallel()

	env := newStubEnv(t, nil, nil)
	ctx := t.Context()
	now := time.Now().Unix()

	env.seedActive(t, "run-holder", validatorcore.StateInviteMinted)
	seedReadyWaiter(t, env.store, "run-waiting", now)

	env.runner.DriveOnce(ctx)
	env.requireState(t, "run-holder", validatorcore.StateInviteMinted)

	waiter, err := env.store.GetTestRun(ctx, "run-waiting")
	if err != nil {
		t.Fatalf("GetTestRun waiter: %v", err)
	}

	if waiter.IsActive || waiter.State != validatorcore.StatePassiveRunning {
		t.Fatalf("waiter is_active=%v state=%q", waiter.IsActive, waiter.State)
	}
}

func TestDriveOnce_MintConflictHardFails(t *testing.T) {
	t.Parallel()

	invites := &stubInvites{mintErr: validatorcore.ErrShareCorrelationConflict}
	env := newStubEnv(t, invites, nil)
	runID := "run-mint-conflict"

	env.seedActive(t, runID, validatorcore.StateActiveRunning)
	env.bindBob(t, runID)

	env.runner.DriveOnce(t.Context())
	env.requireState(t, runID, validatorcore.StateTerminalFail)
	env.requireReason(t, runID, validatorcore.ReasonActiveHardFailCorrelation)
}

func TestDriveOnce_DesignatedCreateUsesAliceTestRunID(t *testing.T) {
	t.Parallel()

	env := newStubEnv(t, nil, nil)
	runID := "run-dispatch-alice"

	env.seedActive(t, runID, validatorcore.StateReverseInviteAccepted)
	env.pinDesignated(t, runID, "omar")

	env.runner.DriveOnce(t.Context())
	env.requireState(t, runID, validatorcore.StateReverseInviteAccepted)

	if env.out.calls != 1 {
		t.Fatalf("CreateAsUser calls = %d, want 1", env.out.calls)
	}

	if env.out.lastID != runID {
		t.Fatalf("alice user id = %q, want test run id", env.out.lastID)
	}

	if env.out.lastReq.ShareWith != "omar@"+testTargetHost {
		t.Fatalf("shareWith = %q, want omar@%s", env.out.lastReq.ShareWith, testTargetHost)
	}

	if env.out.lastReq.ReceiverDomain != testTargetHost {
		t.Fatalf("receiverDomain = %q, want %s", env.out.lastReq.ReceiverDomain, testTargetHost)
	}
}

func TestDriveOnce_DispatchInProgressRetries(t *testing.T) {
	t.Parallel()

	out := &stubOutgoing{err: outgoingshares.ErrDispatchInProgress}
	env := newStubEnv(t, nil, out)
	runID := "run-dispatch-busy"

	env.seedActive(t, runID, validatorcore.StateReverseInviteAccepted)
	env.pinDesignated(t, runID, "omar")

	before := time.Now().Unix() - 3600
	if err := env.store.DB().WithContext(t.Context()).Model(&validatorcore.TestRun{}).
		Where("test_run_id = ?", runID).
		Update("updated_at", before).Error; err != nil {
		t.Fatalf("age updated_at: %v", err)
	}

	env.runner.DriveOnce(t.Context())
	env.requireState(t, runID, validatorcore.StateReverseInviteAccepted)

	if out.calls != 1 {
		t.Fatalf("CreateAsUser calls = %d, want 1", out.calls)
	}

	run, err := env.store.GetTestRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if run.UpdatedAt <= before {
		t.Fatalf("updated_at = %d, want fresher than %d", run.UpdatedAt, before)
	}

	if run.TerminalReason != nil {
		t.Fatalf("terminal_reason = %v, want nil on retry", run.TerminalReason)
	}

	env.runner.DriveOnce(t.Context())

	if out.calls != 2 {
		t.Fatalf("retry CreateAsUser calls = %d, want 2", out.calls)
	}

	env.requireState(t, runID, validatorcore.StateReverseInviteAccepted)
}

func TestDriveOnce_DispatchRefusedHardFails(t *testing.T) {
	t.Parallel()

	out := &stubOutgoing{err: outgoingshares.ErrDispatchRefused}
	env := newStubEnv(t, nil, out)
	runID := "run-dispatch-refused"

	env.seedActive(t, runID, validatorcore.StateReverseInviteAccepted)
	env.pinDesignated(t, runID, "omar")

	env.runner.DriveOnce(t.Context())
	env.requireState(t, runID, validatorcore.StateTerminalFail)
	env.requireReason(t, runID, validatorcore.ReasonActiveHardFailDispatch)
}

func TestDriveOnce_MissingBobHardFailsIdentity(t *testing.T) {
	t.Parallel()

	env := newRealInviteEnv(t)
	runID := "run-missing-bob"

	env.seedActive(t, runID, validatorcore.StateActiveRunning)

	env.runner.DriveOnce(t.Context())
	env.requireState(t, runID, validatorcore.StateTerminalFail)
	env.requireReason(t, runID, validatorcore.ReasonActiveHardFailIdentity)
}

func TestDriveOnce_NoActiveNoWaiterIsNoop(t *testing.T) {
	t.Parallel()

	env := newStubEnv(t, nil, nil)

	env.runner.DriveOnce(t.Context())

	if env.invites.mints != 0 || env.invites.solicits != 0 || env.out.calls != 0 {
		t.Fatalf("empty drive did work: mints=%d solicits=%d creates=%d", env.invites.mints, env.invites.solicits, env.out.calls)
	}
}

func TestDriveOnce_DoesNotSynthesizeOperatorAbort(t *testing.T) {
	t.Parallel()

	invites := &stubInvites{mintErr: validatorcore.ErrShareCorrelationConflict}
	env := newStubEnv(t, invites, nil)
	runID := "run-no-operator-abort"

	env.seedActive(t, runID, validatorcore.StateActiveRunning)
	env.bindBob(t, runID)

	env.runner.DriveOnce(t.Context())
	env.requireReason(t, runID, validatorcore.ReasonActiveHardFailCorrelation)
}
