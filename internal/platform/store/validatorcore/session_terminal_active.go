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
	"time"

	"gorm.io/gorm"
)

// ActiveTerminalUpdate carries the terminal fields written when the active
// session is released. OverallGrade may be nil (an interrupted run carries no
// grade). finished_at and updated_at are stamped by the writer; session_kind
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
// terminal_pass, terminal_fail, or interrupted.
func (c *Core) ReleaseActiveTerminalFrom(
	ctx context.Context,
	testRunID string,
	expectedStates []string,
	update ActiveTerminalUpdate,
) error {
	if c == nil || c.db == nil {
		return errors.New("validatorcore: store is not configured")
	}

	if err := validateActiveTerminalRelease(expectedStates, update.State); err != nil {
		return err
	}

	return c.writeTerminalFields(ctx, testRunID, expectedStates, update)
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

// writeTerminalFields is the shared low-level active-terminalization writer.
// One guarded UPDATE matches the row by test_run_id with is_active=1 and
// state in the caller's expected non-terminal set, and writes is_active=0,
// the terminal state, terminal_reason, updated_at, and overall_grade in the
// same statement; session_kind is left unchanged. finished_at is
// first-write-only: a NULL value gets the current timestamp, an existing
// value is preserved. A zero-row result returns ErrStateTransitionMiss, so a
// row that already moved on is never terminalized a second time. On success,
// expires_at is sealed for rows that opted into permanent retention. Callers
// must validate the expected set and the terminal state before invoking the
// writer.
func (c *Core) writeTerminalFields(
	ctx context.Context,
	testRunID string,
	expectedStates []string,
	update ActiveTerminalUpdate,
) error {
	now := time.Now().Unix()

	err := c.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		res := tx.Model(&TestRun{}).
			Where("test_run_id = ? AND is_active = 1 AND state IN ?", testRunID, expectedStates).
			Updates(map[string]any{
				colIsActive:       false,
				colState:          update.State,
				colFinishedAt:     gorm.Expr("COALESCE("+colFinishedAt+", ?)", now),
				colTerminalReason: update.TerminalReason,
				colUpdatedAt:      now,
				colOverallGrade:   update.OverallGrade,
			})
		if res.Error != nil {
			return res.Error
		}

		if res.RowsAffected == 0 {
			return ErrStateTransitionMiss
		}

		return sealTerminalExpiresAt(tx, testRunID, now)
	})
	if err != nil {
		return fmt.Errorf("validatorcore: release active terminal: %w", err)
	}

	bestEffortPersistTerminalStats(c, ctx, testRunID)

	return nil
}

// sealTerminalExpiresAt stamps expires_at on a just-terminalized row that
// opted into permanent retention: forever keeps expires_at NULL, finite tiers
// expire finished_at + tier days, anchored to the post-update finished_at so
// a preserved first-write value stays the base. Non-permanent rows are never
// sealed.
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
