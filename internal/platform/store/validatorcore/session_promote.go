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

	"github.com/google/uuid"
	"gorm.io/gorm"
)

const extendEligibleSQL = "((state = ? AND opt_in_active = 1) OR (state = ? AND opt_in_active = 0))"

// ExtendToActive promotes a session onto the one-active-run lock.
// Auto-promotion CASes is_active 0->1 from passive_running when
// opt_in_active=1. Opt-out rows may still heal from passive_complete.
// Both paths refuse persisted discovery or TLS fail evidence. bob_user_id
// is minted in the same transaction. A duplicate one-active key is
// OpExtendUpdate. A repeat promote of the same already-active row is a
// successful no-op and does not report a CAS win.
func (c *Core) ExtendToActive(ctx context.Context, testRunID string) error {
	_, err := c.extendToActive(ctx, testRunID)

	return err
}

// ExtendToActiveCAS is the CAS-aware promote. casWon is true only when
// this call performed the passive-to-active transition. An already-active
// row is a successful no-op with casWon false so only the winner triggers
// the shared Bob-then-Kick follow-up.
func (c *Core) ExtendToActiveCAS(ctx context.Context, testRunID string) (bool, error) {
	return c.extendToActive(ctx, testRunID)
}

func (c *Core) extendToActive(ctx context.Context, testRunID string) (bool, error) {
	if c == nil || c.db == nil {
		return false, errors.New("validatorcore: store is not configured")
	}

	now := time.Now().Unix()

	var casWon bool

	err := c.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		won, txErr := extendToActiveTx(tx, testRunID, now)
		casWon = won

		return txErr
	})
	if err != nil {
		return false, fmt.Errorf("validatorcore: extend to active: %w", err)
	}

	return casWon, nil
}

func extendToActiveTx(tx *gorm.DB, testRunID string, now int64) (bool, error) {
	bobID, mintErr := uuid.NewV7()
	if mintErr != nil {
		return false, fmt.Errorf("validatorcore: mint bob user id: %w", mintErr)
	}

	res := tx.Model(&TestRun{}).
		Where(
			"test_run_id = ? AND is_active = 0 AND "+extendEligibleSQL+" AND "+
				notPersistedFailPredicateSQL(),
			testRunID,
			StatePassiveRunning,
			StatePassiveComplete,
			failGatedAreas(),
			failSeverityAliases(),
		).
		Updates(map[string]any{
			colIsActive:  true,
			colState:     StateActiveRunning,
			colBobUserID: bobID.String(),
			colUpdatedAt: now,
		})
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrDuplicatedKey) {
			return false, NewStoreError(OpExtendUpdate, res.Error)
		}

		return false, res.Error
	}

	if res.RowsAffected == 0 {
		return false, extendMissReason(tx, testRunID)
	}

	return true, nil
}

func extendMissReason(tx *gorm.DB, testRunID string) error {
	var row TestRun

	loadErr := tx.First(&row, "test_run_id = ?", testRunID).Error
	if errors.Is(loadErr, gorm.ErrRecordNotFound) {
		return ErrSessionNotFound
	}

	if loadErr != nil {
		return loadErr
	}

	if row.IsActive {
		return nil
	}

	return ErrSessionNotReady
}

// FindOldestReadyOptInWaiter returns the oldest lock-wait row:
// opt_in_active=1, is_active=0, state=passive_running, passive_ready_at set.
// FindOneActive never sees these rows. Missing waiters return
// ErrSessionNotFound.
func (c *Core) FindOldestReadyOptInWaiter(ctx context.Context) (*TestRun, error) {
	if c == nil || c.db == nil {
		return nil, errors.New("validatorcore: store is not configured")
	}

	var row TestRun

	err := c.db.WithContext(ctx).
		Where(
			"opt_in_active = 1 AND is_active = 0 AND state = ? AND passive_ready_at IS NOT NULL",
			StatePassiveRunning,
		).
		Order("passive_ready_at ASC, created_at ASC, test_run_id ASC").
		First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrSessionNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("validatorcore: find ready opt-in waiter: %w", err)
	}

	return &row, nil
}

// PromoteOldestReadyWaiter promotes the oldest ready opt-in waiter when the
// active slot is free. A busy slot leaves the waiter in place. No waiter is
// a successful no-op. A concurrent stop that terminalizes the selected
// waiter after selection and before the CAS is skipped so the next oldest
// ready waiter can take the slot.
func (c *Core) PromoteOldestReadyWaiter(ctx context.Context) error {
	for {
		row, err := c.FindOldestReadyOptInWaiter(ctx)
		if err != nil {
			if errors.Is(err, ErrSessionNotFound) {
				return nil
			}

			return err
		}

		if hook := c.promoteAfterSelectHook; hook != nil {
			hook(row.TestRunID)
		}

		casWon, err := c.extendToActive(ctx, row.TestRunID)
		if err == nil {
			if casWon {
				c.notePromotedWaiter(ctx, row.TestRunID)
			}

			return nil
		}

		if IsActiveSlotBusy(err) {
			return nil
		}

		if !errors.Is(err, ErrSessionNotReady) {
			return err
		}

		skip, loadErr := c.shouldSkipStalePromoteWaiter(ctx, row.TestRunID)
		if loadErr != nil {
			return loadErr
		}

		if skip {
			continue
		}

		return err
	}
}

// shouldSkipStalePromoteWaiter re-reads a CAS miss and reports whether the
// selected waiter is no longer a ready opt-in waiter. That happens when a
// concurrent /stop terminalizes the row between selection and the CAS; the
// miss is then skipped instead of surfaced as ErrSessionNotReady.
func (c *Core) shouldSkipStalePromoteWaiter(ctx context.Context, testRunID string) (bool, error) {
	current, loadErr := c.GetTestRun(ctx, testRunID)
	if loadErr != nil {
		if errors.Is(loadErr, ErrSessionNotFound) {
			return true, nil
		}

		return false, loadErr
	}

	return !IsReadyOptInWaiter(current), nil
}

func (c *Core) notePromotedWaiter(ctx context.Context, testRunID string) {
	if c == nil || testRunID == "" {
		return
	}

	c.RememberPendingPromote(testRunID)
	c.flushPromoteFollowUp(ctx)
}

// RememberPendingPromote records a promoted waiter that still needs
// follow-up. It does not flush, so a deferred Bob-then-Kick can wait
// until the reverse receiver is wired.
func (c *Core) RememberPendingPromote(testRunID string) {
	if c == nil || testRunID == "" {
		return
	}

	c.promoteMu.Lock()
	defer c.promoteMu.Unlock()

	c.lastPromotedID = testRunID
}

// SetPromoteFollowUp binds the shared after-ExtendToActive follow-up.
// The callback returns true when Bob then Kick were delivered so the
// pending id can be consumed. False keeps lastPromotedID so a later
// flush can deliver once the Bob materializer is wired.
func (c *Core) SetPromoteFollowUp(fn func(context.Context, string) bool) {
	if c == nil {
		return
	}

	c.promoteMu.Lock()
	defer c.promoteMu.Unlock()

	c.promoteFollowUp = fn
}

// LastPromotedID is the waiter still waiting for a post-promotion
// follow-up. Empty after that follow-up is delivered or when none
// is pending.
func (c *Core) LastPromotedID() string {
	if c == nil {
		return ""
	}

	c.promoteMu.Lock()
	defer c.promoteMu.Unlock()

	return c.lastPromotedID
}

// FlushPromoteFollowUp runs the bound follow-up for the last CAS-winning
// promotion. A missing hook or promoted id is a no-op so Attach can
// promote before the handler binds the seam. A delivered follow-up
// consumes lastPromotedID so a later flush cannot replay it. The
// callback must not re-enter pending-promote methods; the lock is held
// for the whole flush so concurrent startup, probe, and late-bind
// flushes serialize instead of racing.
func (c *Core) FlushPromoteFollowUp(ctx context.Context) {
	if c == nil {
		return
	}

	c.flushPromoteFollowUp(ctx)
}

func (c *Core) flushPromoteFollowUp(ctx context.Context) {
	if c == nil {
		return
	}

	c.promoteMu.Lock()
	defer c.promoteMu.Unlock()

	fn := c.promoteFollowUp
	id := c.lastPromotedID

	if fn == nil || id == "" {
		return
	}

	if fn(ctx, id) && c.lastPromotedID == id {
		c.lastPromotedID = ""
	}
}

// SetPromoteAfterSelectHook installs a test seam invoked after a ready
// waiter is selected and before ExtendToActive CASes it. Production
// leaves it nil.
func (c *Core) SetPromoteAfterSelectHook(fn func(testRunID string)) {
	if c == nil {
		return
	}

	c.promoteAfterSelectHook = fn
}
