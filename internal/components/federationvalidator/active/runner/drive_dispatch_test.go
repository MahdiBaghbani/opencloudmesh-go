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
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/active/runner"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

func TestDriveOnce_DispatchInProgressRetries(t *testing.T) {
	t.Parallel()

	out := &stubOutgoing{err: outgoingshares.ErrDispatchInProgress}
	env := newStubEnv(t, nil, out)
	runID := "run-dispatch-busy"

	env.seedActive(t, runID, validatorcore.StateReverseInviteAccepted)
	env.pinDesignated(t, runID, "omar")

	now := time.Unix(1_700_000_000, 0)

	clocked, err := runner.New(runner.Deps{
		Store:               env.store,
		Invites:             env.invites,
		Parties:             env.parties,
		LocalIdentity:       testLocalIdentity(),
		ProbeEmail:          testProbeEmail,
		ProbeName:           testProbeName,
		ProbeFilePath:       createProbeFile(t),
		ReapIntervalSeconds: 3600,
		Now:                 func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("runner.New: %v", err)
	}

	clocked.BindOutgoing(out)

	before := now.Unix() - 3600
	env.ageUpdatedAt(t, runID, before)

	clocked.DriveOnce(t.Context())
	env.requireState(t, runID, validatorcore.StateReverseInviteAccepted)

	if out.calls != 1 {
		t.Fatalf("CreateAsUser calls = %d, want 1", out.calls)
	}

	run, getErr := env.store.GetTestRun(t.Context(), runID)
	if getErr != nil {
		t.Fatalf("GetTestRun: %v", getErr)
	}

	if !run.IsActive {
		t.Fatal("in-progress dispatch must keep the run live")
	}

	if run.UpdatedAt != before {
		t.Fatalf("updated_at = %d, want unchanged %d", run.UpdatedAt, before)
	}

	if run.TerminalReason != nil {
		t.Fatalf("terminal_reason = %v, want nil on retry", run.TerminalReason)
	}

	clocked.DriveOnce(t.Context())

	if out.calls != 1 {
		t.Fatalf("in-progress backoff consumed a dispatch attempt: calls = %d, want 1", out.calls)
	}

	now = now.Add(2 * time.Second)

	clocked.DriveOnce(t.Context())

	if out.calls != 2 {
		t.Fatalf("retry CreateAsUser calls = %d, want 2", out.calls)
	}

	env.requireState(t, runID, validatorcore.StateReverseInviteAccepted)
}

func TestDriveOnce_Dispatch5xxRetriesThenHardFails(t *testing.T) {
	t.Parallel()

	fiveXX := &outgoingshares.ReceiverStatusError{Status: http.StatusInternalServerError}
	out := &stubOutgoing{err: fiveXX}
	env := newStubEnv(t, nil, out)
	runID := "run-dispatch-5xx"

	env.seedActive(t, runID, validatorcore.StateReverseInviteAccepted)
	env.pinDesignated(t, runID, "lee")

	now := time.Unix(1_700_000_000, 0)
	clocked := newClockedRunner(t, env, out, &now, 3, 0)

	clocked.DriveOnce(t.Context())
	env.requireState(t, runID, validatorcore.StateReverseInviteAccepted)

	if out.calls != 1 {
		t.Fatalf("CreateAsUser calls = %d, want 1", out.calls)
	}

	clocked.DriveOnce(t.Context())

	if out.calls != 1 {
		t.Fatalf("1s exponential backoff not applied: calls = %d, want 1", out.calls)
	}

	now = now.Add(time.Second)

	clocked.DriveOnce(t.Context())

	if out.calls != 2 {
		t.Fatalf("retry CreateAsUser calls = %d, want 2", out.calls)
	}

	clocked.DriveOnce(t.Context())

	if out.calls != 2 {
		t.Fatalf("2s exponential backoff not applied: calls = %d, want 2", out.calls)
	}

	now = now.Add(time.Second)

	clocked.DriveOnce(t.Context())

	if out.calls != 2 {
		t.Fatalf("2s backoff still pending: calls = %d, want 2", out.calls)
	}

	now = now.Add(time.Second)

	clocked.DriveOnce(t.Context())

	if out.calls != 3 {
		t.Fatalf("exhausting CreateAsUser calls = %d, want 3", out.calls)
	}

	env.requireState(t, runID, validatorcore.StateTerminalFail)
	env.requireReason(t, runID, validatorcore.ReasonActiveHardFailDispatch)
}

func TestDriveOnce_SuccessResetsDispatchRetryBudget(t *testing.T) {
	t.Parallel()

	fiveXX := &outgoingshares.ReceiverStatusError{Status: http.StatusInternalServerError}
	out := &stubOutgoing{err: fiveXX}
	env := newStubEnv(t, nil, out)
	runID := "run-dispatch-success-reset"

	env.seedActive(t, runID, validatorcore.StateReverseInviteAccepted)
	env.pinDesignated(t, runID, "lee")

	now := time.Unix(1_700_000_000, 0)
	clocked := newClockedRunner(t, env, out, &now, 2, 0)

	clocked.DriveOnce(t.Context())
	env.requireState(t, runID, validatorcore.StateReverseInviteAccepted)

	if out.calls != 1 {
		t.Fatalf("CreateAsUser calls = %d, want 1", out.calls)
	}

	clocked.DriveOnce(t.Context())

	if out.calls != 1 {
		t.Fatalf("1s exponential backoff not applied: calls = %d, want 1", out.calls)
	}

	now = now.Add(time.Second)
	out.err = nil

	clocked.DriveOnce(t.Context())

	if out.calls != 2 {
		t.Fatalf("successful retry CreateAsUser calls = %d, want 2", out.calls)
	}

	env.requireState(t, runID, validatorcore.StateReverseInviteAccepted)

	out.err = fiveXX

	clocked.DriveOnce(t.Context())

	if out.calls != 3 {
		t.Fatalf("first new failure CreateAsUser calls = %d, want 3", out.calls)
	}

	env.requireState(t, runID, validatorcore.StateReverseInviteAccepted)

	clocked.DriveOnce(t.Context())

	if out.calls != 3 {
		t.Fatalf("fresh backoff consumed a dispatch attempt: calls = %d, want 3", out.calls)
	}

	now = now.Add(time.Second)

	clocked.DriveOnce(t.Context())

	if out.calls != 4 {
		t.Fatalf("exhausting fresh budget CreateAsUser calls = %d, want 4", out.calls)
	}

	env.requireState(t, runID, validatorcore.StateTerminalFail)
	env.requireReason(t, runID, validatorcore.ReasonActiveHardFailDispatch)
}

func TestDriveOnce_DispatchInProgressDoesNotConsumeDispatchAttempts(t *testing.T) {
	t.Parallel()

	out := &stubOutgoing{err: outgoingshares.ErrDispatchInProgress}
	env := newStubEnv(t, nil, out)
	runID := "run-dispatch-inprogress-budget"

	env.seedActive(t, runID, validatorcore.StateReverseInviteAccepted)
	env.pinDesignated(t, runID, "omar")

	now := time.Unix(1_700_000_000, 0)
	clocked := newClockedRunner(t, env, out, &now, 2, 0)

	clocked.DriveOnce(t.Context())

	if out.calls != 1 {
		t.Fatalf("CreateAsUser calls = %d, want 1", out.calls)
	}

	clocked.DriveOnce(t.Context())

	if out.calls != 1 {
		t.Fatalf("in-progress backoff consumed a call: calls = %d, want 1", out.calls)
	}

	now = now.Add(time.Second)

	clocked.DriveOnce(t.Context())

	if out.calls != 2 {
		t.Fatalf("in-progress retry calls = %d, want 2", out.calls)
	}

	now = now.Add(2 * time.Second)

	clocked.DriveOnce(t.Context())

	if out.calls != 3 {
		t.Fatalf("second in-progress retry calls = %d, want 3", out.calls)
	}

	env.requireState(t, runID, validatorcore.StateReverseInviteAccepted)

	out.err = &outgoingshares.ReceiverStatusError{Status: http.StatusInternalServerError}
	now = now.Add(4 * time.Second)

	clocked.DriveOnce(t.Context())

	if out.calls != 4 {
		t.Fatalf("first 5xx after in-progress calls = %d, want 4", out.calls)
	}

	env.requireState(t, runID, validatorcore.StateReverseInviteAccepted)

	now = now.Add(time.Second)

	clocked.DriveOnce(t.Context())

	if out.calls != 5 {
		t.Fatalf("exhausting 5xx calls = %d, want 5", out.calls)
	}

	env.requireState(t, runID, validatorcore.StateTerminalFail)
	env.requireReason(t, runID, validatorcore.ReasonActiveHardFailDispatch)
}

func TestDriveOnce_Dispatch400And403HardFailOnFirstTick(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		status int
		runID  string
	}{
		{
			name:   "400",
			status: http.StatusBadRequest,
			runID:  "run-dispatch-400",
		},
		{
			name:   "403",
			status: http.StatusForbidden,
			runID:  "run-dispatch-403",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			refused := &outgoingshares.ReceiverStatusError{Status: tt.status}
			out := &stubOutgoing{err: refused}
			env := newStubEnv(t, nil, out)

			env.seedActive(t, tt.runID, validatorcore.StateReverseInviteAccepted)
			env.pinDesignated(t, tt.runID, "omar")

			now := time.Unix(1_700_000_000, 0)
			clocked := newClockedRunner(t, env, out, &now, 5, 0)

			clocked.DriveOnce(t.Context())
			env.requireState(t, tt.runID, validatorcore.StateTerminalFail)
			env.requireReason(t, tt.runID, validatorcore.ReasonActiveHardFailDispatch)

			if out.calls != 1 {
				t.Fatalf("CreateAsUser calls = %d, want 1", out.calls)
			}

			clocked.DriveOnce(t.Context())

			if out.calls != 1 {
				t.Fatalf("permanent refuse scheduled a retry: calls = %d, want 1", out.calls)
			}

			now = now.Add(time.Hour)

			clocked.DriveOnce(t.Context())

			if out.calls != 1 {
				t.Fatalf("permanent refuse retried after clock advance: calls = %d, want 1", out.calls)
			}
		})
	}
}

func TestDriveOnce_HardFailPersistFailureKeepsRetryBudget(t *testing.T) {
	t.Parallel()

	fiveXX := &outgoingshares.ReceiverStatusError{Status: http.StatusInternalServerError}
	out := &stubOutgoing{err: fiveXX}
	env := newStubEnv(t, nil, out)
	runID := "run-hardfail-persist-budget"

	env.seedActive(t, runID, validatorcore.StateReverseInviteAccepted)
	env.pinDesignated(t, runID, "lee")

	now := time.Unix(1_700_000_000, 0)
	clocked := newClockedRunner(t, env, out, &now, 1, 0)

	failNextTestRunUpdate(t, env.store)

	clocked.DriveOnce(t.Context())
	env.requireState(t, runID, validatorcore.StateReverseInviteAccepted)

	if out.calls != 1 {
		t.Fatalf("CreateAsUser calls = %d, want 1", out.calls)
	}

	run, err := env.store.GetTestRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if !run.IsActive {
		t.Fatal("failed hard-fail persist must keep the run live")
	}

	if run.TerminalReason != nil {
		t.Fatalf("terminal_reason = %v, want nil after persist failure", run.TerminalReason)
	}

	clocked.DriveOnce(t.Context())

	if out.calls != 1 {
		t.Fatalf("retry budget reset after persist failure: calls = %d, want 1", out.calls)
	}

	now = now.Add(time.Second)

	clocked.DriveOnce(t.Context())

	if out.calls != 2 {
		t.Fatalf("later persist retry calls = %d, want 2", out.calls)
	}

	env.requireState(t, runID, validatorcore.StateTerminalFail)
	env.requireReason(t, runID, validatorcore.ReasonActiveHardFailDispatch)
	env.requireInactive(t, runID)
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
