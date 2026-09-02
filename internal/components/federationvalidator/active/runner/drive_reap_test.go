// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package runner_test

import (
	"net/http"
	"testing"
	"time"

	outgoingshares "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api/outgoing/shares"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

func TestReapOnce_PendingRetrySkipsIdleTimeout(t *testing.T) {
	t.Parallel()

	t.Run("backoff-retrying live handle stays live", func(t *testing.T) {
		t.Parallel()

		fiveXX := &outgoingshares.ReceiverStatusError{Status: http.StatusInternalServerError}
		out := &stubOutgoing{err: fiveXX}
		env := newStubEnv(t, nil, out)
		runID := "run-watch-backoff"

		env.seedActive(t, runID, validatorcore.StateReverseInviteAccepted)
		env.pinDesignated(t, runID, "omar")

		now := time.Unix(1_700_000_000, 0)
		clocked := newClockedRunner(t, env, out, &now, 5, 10)
		t.Cleanup(clocked.Stop)

		clocked.DriveOnce(t.Context())
		env.requireState(t, runID, validatorcore.StateReverseInviteAccepted)

		if out.calls != 1 {
			t.Fatalf("CreateAsUser calls = %d, want 1", out.calls)
		}

		aged := now.Unix() - 100
		env.ageUpdatedAt(t, runID, aged)

		before, err := env.store.GetTestRun(t.Context(), runID)
		if err != nil {
			t.Fatalf("GetTestRun before reap: %v", err)
		}

		clocked.ReapOnce()

		env.requireState(t, runID, validatorcore.StateReverseInviteAccepted)

		run, err := env.store.GetTestRun(t.Context(), runID)
		if err != nil {
			t.Fatalf("GetTestRun: %v", err)
		}

		if !run.IsActive {
			t.Fatal("backoff-retrying live handle was watchdog-terminalized")
		}

		if run.TerminalReason != nil {
			t.Fatalf("terminal_reason = %v, want nil", run.TerminalReason)
		}

		if run.UpdatedAt != before.UpdatedAt {
			t.Fatalf("updated_at = %d, want unchanged %d", run.UpdatedAt, before.UpdatedAt)
		}
	})

	t.Run("in-progress retry live handle stays live", func(t *testing.T) {
		t.Parallel()

		out := &stubOutgoing{err: outgoingshares.ErrDispatchInProgress}
		env := newStubEnv(t, nil, out)
		runID := "run-watch-inprogress"

		env.seedActive(t, runID, validatorcore.StateReverseInviteAccepted)
		env.pinDesignated(t, runID, "omar")

		now := time.Unix(1_700_000_000, 0)
		clocked := newClockedRunner(t, env, out, &now, 5, 10)
		t.Cleanup(clocked.Stop)

		clocked.DriveOnce(t.Context())
		env.requireState(t, runID, validatorcore.StateReverseInviteAccepted)

		if out.calls != 1 {
			t.Fatalf("CreateAsUser calls = %d, want 1", out.calls)
		}

		aged := now.Unix() - 100
		env.ageUpdatedAt(t, runID, aged)

		before, err := env.store.GetTestRun(t.Context(), runID)
		if err != nil {
			t.Fatalf("GetTestRun before reap: %v", err)
		}

		clocked.ReapOnce()

		env.requireState(t, runID, validatorcore.StateReverseInviteAccepted)

		run, err := env.store.GetTestRun(t.Context(), runID)
		if err != nil {
			t.Fatalf("GetTestRun: %v", err)
		}

		if !run.IsActive {
			t.Fatal("in-progress retry live handle was watchdog-terminalized")
		}

		if run.TerminalReason != nil {
			t.Fatalf("terminal_reason = %v, want nil", run.TerminalReason)
		}

		if run.UpdatedAt != before.UpdatedAt {
			t.Fatalf("updated_at = %d, want unchanged %d", run.UpdatedAt, before.UpdatedAt)
		}
	})

	t.Run("idle live handle is interrupted", func(t *testing.T) {
		t.Parallel()

		env := newStubEnv(t, nil, nil)
		runID := "run-watch-idle"

		env.seedActive(t, runID, validatorcore.StateReverseInviteAccepted)

		now := time.Unix(1_700_000_000, 0)
		clocked := newClockedRunner(t, env, env.out, &now, 5, 10)
		t.Cleanup(clocked.Stop)

		env.ageUpdatedAt(t, runID, now.Unix()-100)

		clocked.ReapOnce()

		env.requireInactive(t, runID)
		env.requireState(t, runID, validatorcore.StateInterrupted)
		env.requireReason(t, runID, validatorcore.ReasonActiveDriveTimeout)
	})
}

// TestReapOnce_SuccessfulDriveOnceDoesNotTimeoutAgedRow proves the
// preferred watchdog contract: successful DriveOnce is live progress,
// so an aged ReapOnce must not terminalize. The runner records that
// progress on DriveOnce retry state instead of bumping updated_at,
// which would hide a genuinely stuck remote from later idle reaps.
// The same retry state is reset (fresh budget, no pending wait) so a
// later DriveOnce can dispatch immediately.
func TestReapOnce_SuccessfulDriveOnceDoesNotTimeoutAgedRow(t *testing.T) {
	t.Parallel()

	fiveXX := &outgoingshares.ReceiverStatusError{Status: http.StatusInternalServerError}
	out := &stubOutgoing{}
	env := newStubEnv(t, nil, out)
	runID := "run-watch-after-success"

	env.seedActive(t, runID, validatorcore.StateReverseInviteAccepted)
	env.pinDesignated(t, runID, "omar")

	now := time.Unix(1_700_000_000, 0)
	clocked := newClockedRunner(t, env, out, &now, 2, 10)
	t.Cleanup(clocked.Stop)

	clocked.DriveOnce(t.Context())
	env.requireState(t, runID, validatorcore.StateReverseInviteAccepted)

	if out.calls != 1 {
		t.Fatalf("CreateAsUser calls = %d, want 1", out.calls)
	}

	aged := now.Unix() - 100
	env.ageUpdatedAt(t, runID, aged)

	clocked.ReapOnce()

	env.requireState(t, runID, validatorcore.StateReverseInviteAccepted)

	run, err := env.store.GetTestRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if !run.IsActive {
		t.Fatal("successful DriveOnce was watchdog-terminalized on aged ReapOnce")
	}

	if run.TerminalReason != nil {
		t.Fatalf("terminal_reason = %v, want nil", run.TerminalReason)
	}

	if run.UpdatedAt != aged {
		t.Fatalf("updated_at = %d, want unchanged %d", run.UpdatedAt, aged)
	}

	out.err = fiveXX

	clocked.DriveOnce(t.Context())

	if out.calls != 2 {
		t.Fatalf("fresh budget after success blocked: calls = %d, want 2", out.calls)
	}

	env.requireState(t, runID, validatorcore.StateReverseInviteAccepted)

	run, err = env.store.GetTestRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetTestRun after fresh failure: %v", err)
	}

	if !run.IsActive {
		t.Fatal("fresh-budget failure after success terminalized the run")
	}

	if run.UpdatedAt != aged {
		t.Fatalf("updated_at after fresh failure = %d, want unchanged %d", run.UpdatedAt, aged)
	}
}
