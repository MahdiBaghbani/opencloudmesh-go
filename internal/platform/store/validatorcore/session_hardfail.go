// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"context"
	"errors"
	"fmt"
	"slices"
)

// Hard-fail terminal reasons form a closed set. The writer rejects any
// non-empty reason outside the set before the guarded update runs, and an
// empty reason normalizes to ReasonActiveHardFail. Every reason in the set
// is unflippable: none of them is a timeout reason a later flip transition
// may rewrite.
//
// hardFailReasons is the closed set of hard-fail terminal reasons.
var hardFailReasons = []string{
	ReasonActiveHardFail,
	ReasonActiveHardFailIdentity,
	ReasonActiveHardFailDispatch,
	ReasonActiveHardFailCorrelation,
	ReasonOperatorAborted,
	ReasonWrongAccepter,
}

// hardFailProtectedStates are the in-flight graded exercise states. A
// hard-fail carrying any reason other than ReasonActiveHardFailIdentity is
// refused here, so a late failure signal cannot steal a run that can still
// produce a pass. The set mirrors the pass-capable pre-image in
// ActivePassExpectedStates but is kept independent: the refusal guard must
// not silently change when the pass set evolves.
var hardFailProtectedStates = []string{StateCapabilityExercise, StateReverseAwaitingShare}

// ReleaseActiveHardFail terminalizes the active session as terminal_fail
// with the caller's reason and GradeFail. The guarded update requires is_active=1 and
// state NOT IN the terminal states, so an already-terminal or
// already-released row is never rewritten and the guard never enumerates the
// non-terminal forward names. The exclusion is reason-conditional: the
// identity reason keeps the bare terminal exclusion and may interrupt any
// non-terminal state, while every other reason additionally excludes the
// graded exercise states and is answered with ErrActiveHardFailRefused when
// the run sits in one of them. Terminal statistics persist best-effort after
// the state transition through the shared active-terminal release path.
func (c *Core) ReleaseActiveHardFail(ctx context.Context, testRunID, reason string) error {
	if c == nil || c.db == nil {
		return errors.New("validatorcore: store is not configured")
	}

	normalized, err := normalizeHardFailReason(reason)
	if err != nil {
		return err
	}

	grade := GradeFail

	err = c.ReleaseActiveTerminalExcept(ctx, testRunID, hardFailExclusions(normalized), ActiveTerminalUpdate{
		State:          StateTerminalFail,
		TerminalReason: normalized,
		OverallGrade:   &grade,
	})
	if errors.Is(err, ErrStateTransitionMiss) {
		return c.diagnoseHardFailMiss(ctx, testRunID, normalized)
	}

	return err
}

// normalizeHardFailReason maps an empty reason to the canonical default and
// rejects any non-empty reason outside the closed set, so free text never
// reaches the guarded update.
func normalizeHardFailReason(reason string) (string, error) {
	if reason == "" {
		return ReasonActiveHardFail, nil
	}

	if !slices.Contains(hardFailReasons, reason) {
		return "", fmt.Errorf("validatorcore: hard-fail reason %q: %w", reason, ErrActiveHardFailReasonInvalid)
	}

	return reason, nil
}

// hardFailExclusions builds the reason-conditional exclusion set beyond the
// terminal states the writer always excludes. The identity reason adds
// nothing; every other reason adds the graded exercise states, so the
// refusal holds at SQL level regardless of timing.
func hardFailExclusions(reason string) []string {
	if reason == ReasonActiveHardFailIdentity {
		return nil
	}

	return hardFailProtectedStates
}

// diagnoseHardFailMiss distinguishes a refusal from an ordinary miss after
// the guarded update matched no row. The read is advisory only: the refusal
// itself is enforced by the exclusion set, never by this lookup.
func (c *Core) diagnoseHardFailMiss(ctx context.Context, testRunID, reason string) error {
	if reason == ReasonActiveHardFailIdentity {
		return ErrStateTransitionMiss
	}

	var row TestRun

	err := c.db.WithContext(ctx).
		Select(colIsActive, colState).
		Where("test_run_id = ?", testRunID).
		First(&row).Error
	if err != nil || !row.IsActive {
		return ErrStateTransitionMiss
	}

	if slices.Contains(hardFailProtectedStates, row.State) {
		return fmt.Errorf("validatorcore: hard-fail in %s: %w", row.State, ErrActiveHardFailRefused)
	}

	return ErrStateTransitionMiss
}
