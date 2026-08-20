// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"errors"
	"testing"
)

func TestReleaseActiveHardFail_ClosedReasonSet(t *testing.T) {
	t.Parallel()

	t.Run("empty reason normalizes to the default", func(t *testing.T) {
		t.Parallel()

		core := openTestCore(t)
		ctx := t.Context()
		runID := "run-hardfail-empty-reason"

		seedActiveRunInState(t, core, runID, StateActiveRunning)

		if err := core.ReleaseActiveHardFail(ctx, runID, ""); err != nil {
			t.Fatalf("ReleaseActiveHardFail with empty reason: %v", err)
		}

		got, err := core.GetTestRun(ctx, runID)
		if err != nil {
			t.Fatalf("GetTestRun: %v", err)
		}

		if got.State != StateTerminalFail {
			t.Fatalf("state = %q, want %q", got.State, StateTerminalFail)
		}

		if got.TerminalReason == nil || *got.TerminalReason != ReasonActiveHardFail {
			t.Fatalf("terminal_reason = %v, want default %q", got.TerminalReason, ReasonActiveHardFail)
		}
	})

	t.Run("free text rejected before the update", func(t *testing.T) {
		t.Parallel()

		core := openTestCore(t)
		ctx := t.Context()
		runID := "run-hardfail-free-text"

		seedActiveRunInState(t, core, runID, StateActiveRunning)

		err := core.ReleaseActiveHardFail(ctx, runID, "not_a_reason")
		if !errors.Is(err, ErrActiveHardFailReasonInvalid) {
			t.Fatalf("error = %v, want ErrActiveHardFailReasonInvalid", err)
		}

		assertActiveInState(t, core, runID, StateActiveRunning)
	})

	for _, reason := range hardFailReasons {
		t.Run("closed set member "+reason, func(t *testing.T) {
			t.Parallel()

			core := openTestCore(t)
			ctx := t.Context()
			runID := "run-hardfail-reason-" + reason

			seedActiveRunInState(t, core, runID, StateActiveRunning)

			if err := core.ReleaseActiveHardFail(ctx, runID, reason); err != nil {
				t.Fatalf("ReleaseActiveHardFail with %q: %v", reason, err)
			}

			got, err := core.GetTestRun(ctx, runID)
			if err != nil {
				t.Fatalf("GetTestRun: %v", err)
			}

			if got.TerminalReason == nil || *got.TerminalReason != reason {
				t.Fatalf("terminal_reason = %v, want %q", got.TerminalReason, reason)
			}
		})
	}
}
