// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"context"
	"slices"

	"gorm.io/gorm"
)

// ActiveTerminalUpdate carries the terminal fields written on a first-write
// terminal transition. OverallGrade may be nil (an interrupted run carries no
// grade). finished_at and updated_at are stamped by WriteTerminal; session_kind
// is never rewritten.
type ActiveTerminalUpdate struct {
	State          string
	TerminalReason string
	OverallGrade   *string
}

// ActivePassExpectedStates returns the expected-state set for releasing a
// successful active session into terminal_pass: the capability exercise and
// the reverse-share wait are the two states a passing run can still occupy.
func ActivePassExpectedStates() []string {
	return []string{StateCapabilityExercise, StateReverseAwaitingShare}
}

// ReleaseActiveTerminal terminalizes the active session from a single
// expected non-terminal state. See ReleaseActiveTerminalFrom.
func (c *Core) ReleaseActiveTerminal(
	ctx context.Context,
	testRunID string,
	expectedState string,
	update ActiveTerminalUpdate,
) error {
	return c.ReleaseActiveTerminalFrom(ctx, testRunID, []string{expectedState}, update)
}

// ReleaseActiveTerminalFrom terminalizes the active session when its current
// state is in expectedStates. The set must be non-empty (empty never means
// any) and must not contain a terminal state, so an already-terminal row can
// never match and is never rewritten. update.State must be one of
// terminal_pass, terminal_fail, or interrupted. The first-write lands through
// WriteTerminal.
func (c *Core) ReleaseActiveTerminalFrom(
	ctx context.Context,
	testRunID string,
	expectedStates []string,
	update ActiveTerminalUpdate,
) error {
	return c.WriteTerminal(ctx, testRunID, true, expectedStates, update)
}

func validateActiveTerminalRelease(expectedStates []string, terminalState string) error {
	if len(expectedStates) == 0 {
		return ErrTerminalExpectedStatesEmpty
	}

	if slices.ContainsFunc(expectedStates, isTerminalState) {
		return ErrTerminalExpectedStatesTerminal
	}

	if !isTerminalState(terminalState) {
		return ErrTerminalStateInvalid
	}

	return nil
}

// ReleaseActiveTerminalExcept terminalizes the active session from any
// non-terminal state not listed in extraExcludedStates. This is the
// name-agnostic complement of ReleaseActiveTerminalFrom: the guarded update
// matches state NOT IN the exclusion set instead of enumerating the
// non-terminal pre-image, so callers that must fire on every non-terminal
// state do not drift when the state enum grows. The terminal states are
// always excluded by construction, so an already-terminal row can never
// match and is never rewritten; an empty extra set therefore means any
// non-terminal state. update.State must be terminal. The first-write lands
// through WriteTerminal.
func (c *Core) ReleaseActiveTerminalExcept(
	ctx context.Context,
	testRunID string,
	extraExcludedStates []string,
	update ActiveTerminalUpdate,
) error {
	return c.writeTerminalExcept(ctx, testRunID, extraExcludedStates, update)
}

func validateActiveTerminalExclusion(extraExcludedStates []string, terminalState string) error {
	if slices.ContainsFunc(extraExcludedStates, isTerminalState) {
		return ErrTerminalExclusionTerminal
	}

	if !isTerminalState(terminalState) {
		return ErrTerminalStateInvalid
	}

	return nil
}

// sealTerminalExpiresAt stamps expires_at on a just-terminalized row that
// opted into permanent retention: forever keeps expires_at NULL, finite tiers
// expire finished_at + tier days, anchored to the post-update finished_at so
// a preserved first-write value stays the base. Non-permanent rows are never
// sealed. Hybrid lock repair also uses this helper without rewriting terminal
// fields or persisting statistics.
func sealTerminalExpiresAt(tx *gorm.DB, testRunID string, finishedAt int64) error {
	var row TestRun

	if err := tx.Where("test_run_id = ? AND is_active = 0", testRunID).First(&row).Error; err != nil {
		return err
	}

	if !PermanentOptedIn(&row) {
		return nil
	}

	base := finishedAt
	if row.FinishedAt != nil {
		base = *row.FinishedAt
	}

	// A missing or invalid tier must still receive a sweepable finite expiry,
	// so fall back to the default tier instead of leaving expires_at NULL.
	tier := DefaultRetentionTier
	if row.RetentionTier != nil && ValidRetentionTier(*row.RetentionTier) {
		tier = *row.RetentionTier
	}

	days, forever, _ := RetentionTierDays(tier)

	var expiresAt *int64

	if !forever {
		expires := base + int64(days)*SecondsPerDay
		expiresAt = &expires
	}

	return tx.Model(&TestRun{}).
		Where("test_run_id = ? AND is_active = 0", testRunID).
		Updates(map[string]any{colExpiresAt: expiresAt}).Error
}
