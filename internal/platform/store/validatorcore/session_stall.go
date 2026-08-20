// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"
)

// SweepStalledActiveSessions runs one stall-maintenance pass over the
// active-run lock. It first reconciles rows that already hold a terminal
// state while still marked active (a partial terminal write): only the
// active lock is cleared, a missing finished_at is first-written once, and
// an unsealed permanent row is sealed from its finished_at; already-written
// terminal fields stay untouched and no statistics are persisted again. It
// then interrupts active runs still in a non-terminal state whose updated_at
// is older than the configured stall timeout; the guarded state/lock
// transition to interrupted lands first and terminal statistics persist
// best-effort afterwards through the shared active-terminal release path.
// The pass never deletes rows and never stamps harvest markers, so
// probe-linked sessions survive interruption.
func (c *Core) SweepStalledActiveSessions(ctx context.Context) error {
	if c == nil || c.db == nil {
		return errors.New("validatorcore: store is not configured")
	}

	if err := c.releaseActiveTerminalHybrids(ctx); err != nil {
		return err
	}

	return c.interruptStalledActiveRuns(ctx)
}

// releaseActiveTerminalHybrids reconciles rows whose state is already
// terminal while the active lock is still held. Each row is repaired in its
// own transaction: the lock clear matches only is_active=1 rows in the
// terminal set, so a row still mid-transition is never touched and a row
// already released is a no-op.
func (c *Core) releaseActiveTerminalHybrids(ctx context.Context) error {
	var rows []TestRun

	if err := c.db.WithContext(ctx).
		Select(colTestRunID, colExpiresAt).
		Where("is_active = 1 AND state IN ?", terminalStateSet()).
		Find(&rows).Error; err != nil {
		return fmt.Errorf("validatorcore: list active terminal hybrids: %w", err)
	}

	now := time.Now().Unix()

	for _, row := range rows {
		if err := c.releaseActiveTerminalHybrid(ctx, row, now); err != nil {
			return err
		}
	}

	return nil
}

// releaseActiveTerminalHybrid clears the active lock on one terminal hybrid
// without rewriting already-written terminal fields. finished_at is
// first-write-only at SQL level: the UPDATE stamps COALESCE(finished_at, now),
// so a concurrent first-write that landed after the selection read is
// preserved instead of overwritten by the stale pre-transaction snapshot.
// When the row opted into permanent retention and expires_at is still NULL,
// the shared seal helper derives the expiry from the row's finished_at; a
// non-NULL expires_at is never rewritten. No statistics are persisted here.
func (c *Core) releaseActiveTerminalHybrid(ctx context.Context, row TestRun, now int64) error {
	err := c.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		res := tx.Model(&TestRun{}).
			Where("test_run_id = ? AND is_active = 1 AND state IN ?", row.TestRunID, terminalStateSet()).
			Updates(map[string]any{
				colIsActive:   false,
				colFinishedAt: gorm.Expr("COALESCE("+colFinishedAt+", ?)", now),
			})
		if res.Error != nil {
			return res.Error
		}

		if res.RowsAffected == 0 {
			return nil
		}

		if row.ExpiresAt != nil {
			return nil
		}

		// The selection read raced with a concurrent seal; re-check under
		// the transaction's write lock so a non-NULL expires_at is never
		// rewritten.
		var current TestRun
		if err := tx.Select(colExpiresAt).
			Where("test_run_id = ?", row.TestRunID).
			First(&current).Error; err != nil {
			return err
		}

		if current.ExpiresAt != nil {
			return nil
		}

		return sealTerminalExpiresAt(tx, row.TestRunID, now)
	})
	if err != nil {
		return fmt.Errorf("validatorcore: release active terminal hybrid: %w", err)
	}

	return nil
}

// interruptStalledActiveRuns moves active runs that stopped making progress
// to interrupted. Selection guards on state NOT IN the terminal set rather
// than a per-state list, so any non-terminal state is swept regardless of its
// name. A transition miss means the run moved on between selection and the
// guarded write and is skipped.
func (c *Core) interruptStalledActiveRuns(ctx context.Context) error {
	cfg := c.SessionConfig()
	if cfg.StallTimeoutSeconds <= 0 {
		return nil
	}

	cutoff := time.Now().Unix() - int64(cfg.StallTimeoutSeconds)

	var rows []TestRun

	if err := c.db.WithContext(ctx).
		Select(colTestRunID, colState).
		Where("is_active = 1 AND state NOT IN ? AND updated_at < ?", terminalStateSet(), cutoff).
		Find(&rows).Error; err != nil {
		return fmt.Errorf("validatorcore: list stalled active runs: %w", err)
	}

	for _, row := range rows {
		err := c.ReleaseActiveTerminalFrom(ctx, row.TestRunID, []string{row.State}, ActiveTerminalUpdate{
			State:          StateInterrupted,
			TerminalReason: stallTerminalReason(row.State),
		})
		if err == nil || errors.Is(err, ErrStateTransitionMiss) {
			continue
		}

		return err
	}

	return nil
}

// stallTerminalReason maps a stalled non-terminal state to its terminal
// reason. The reverse waits have dedicated timeout reasons; every other
// stalled state reads as inactivity expiry.
func stallTerminalReason(state string) string {
	switch state {
	case StateReverseAwaitingShare:
		return "reverse_share_timeout"
	case StateReverseAwaitingInvite:
		return "reverse_invite_timeout"
	default:
		return "stall_inactivity_expired"
	}
}

// terminalStateSet builds the terminal exclusion list from the session state
// enum and the terminal predicate, so the sweep never enumerates non-terminal
// forward names and interrupted stays in the terminal set by construction.
func terminalStateSet() []string {
	states := make([]string, 0, len(testRunStates))

	for _, state := range testRunStates {
		if isTerminalState(state) {
			states = append(states, state)
		}
	}

	return states
}
