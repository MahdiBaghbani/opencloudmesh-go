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

	"github.com/google/uuid"
	"gorm.io/gorm"
)

const extendEligibleSQL = "((state = ? AND opt_in_active = 1) OR (state = ? AND opt_in_active = 0))"

// ExtendToActive promotes a session onto that target's active-run lock.
// Auto-promotion CASes is_active 0->1 from passive_running when
// opt_in_active=1. Opt-out rows may still heal from passive_complete.
// Both paths refuse persisted discovery or TLS fail evidence. bob_user_id
// is minted in the same transaction. A duplicate per-target active key is
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

func (c *Core) listReadyWaiterTargetHosts(ctx context.Context) ([]string, error) {
	if c == nil || c.db == nil {
		return nil, errors.New("validatorcore: store is not configured")
	}

	hosts := []string{}

	err := c.db.WithContext(ctx).Raw(
		"SELECT DISTINCT target_host FROM test_run WHERE opt_in_active = 1 "+
			"AND is_active = 0 AND state = ? AND passive_ready_at IS NOT NULL "+
			"ORDER BY target_host ASC",
		StatePassiveRunning,
	).Scan(&hosts).Error
	if err != nil {
		return nil, fmt.Errorf("validatorcore: list ready waiter target hosts: %w", err)
	}

	if hosts == nil {
		hosts = []string{}
	}

	return hosts, nil
}

func (c *Core) promoteOldestReadyWaiterForTarget(ctx context.Context, targetHost string) error {
	for {
		row, err := c.FindOldestReadyWaiterForTarget(ctx, targetHost)
		if err != nil {
			if errors.Is(err, ErrSessionNotFound) {
				return nil
			}

			return err
		}

		_, activeErr := c.FindActiveByTarget(ctx, targetHost)
		if activeErr == nil {
			return nil
		}

		if !errors.Is(activeErr, gorm.ErrRecordNotFound) {
			return activeErr
		}

		if hook := c.promoteAfterSelectHook; hook != nil {
			hook(row.TestRunID)
		}

		casWon, err := c.ExtendToActiveCAS(ctx, row.TestRunID)
		if err == nil {
			if casWon {
				c.notePromotedWaiter(ctx, row.TestRunID)
			}

			return nil
		}

		if IsTargetSlotBusy(err) {
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

// PromoteOldestReadyWaiter promotes the oldest ready opt-in waiter for each
// requested target when that target's active slot is free. An omitted or
// empty host iterates every target that currently has a ready waiter, in
// ascending host order. A non-empty host is handled alone. A busy slot
// leaves that target's waiter in place and does not stop other hosts. No
// waiter is a successful no-op. A concurrent stop that terminalizes the
// selected waiter after selection and before the CAS is skipped so the next
// oldest ready waiter for the same target can take the slot.
func (c *Core) PromoteOldestReadyWaiter(ctx context.Context, targetHosts ...string) error {
	hosts := make([]string, 0, len(targetHosts))
	for _, host := range targetHosts {
		if host != "" {
			hosts = append(hosts, host)
		}
	}

	if len(hosts) == 0 {
		listed, err := c.listReadyWaiterTargetHosts(ctx)
		if err != nil {
			return err
		}

		hosts = listed
	}

	for _, host := range hosts {
		if err := c.promoteOldestReadyWaiterForTarget(ctx, host); err != nil {
			return err
		}
	}

	return nil
}

// shouldSkipStalePromoteWaiter re-reads a CAS miss and reports whether the
// selected waiter is no longer a ready opt-in waiter with no persisted
// discovery or TLS fail evidence. That happens when a concurrent /stop
// terminalizes the row between selection and the CAS, or when fail
// evidence lands in the same window; the miss is then skipped instead of
// surfaced as ErrSessionNotReady. A waiter that still satisfies the
// ready opt-in plus fail-evidence CAS predicate is a genuine not-ready
// condition and is not skipped.
func (c *Core) shouldSkipStalePromoteWaiter(ctx context.Context, testRunID string) (bool, error) {
	current, loadErr := c.GetTestRun(ctx, testRunID)
	if loadErr != nil {
		if errors.Is(loadErr, ErrSessionNotFound) {
			return true, nil
		}

		return false, loadErr
	}

	if !IsReadyOptInWaiter(current) {
		return true, nil
	}

	var eligible int64

	err := c.db.WithContext(ctx).Model(&TestRun{}).
		Where(
			"test_run_id = ? AND "+notPersistedFailPredicateSQL(),
			testRunID,
			failGatedAreas(),
			failSeverityAliases(),
		).
		Count(&eligible).Error
	if err != nil {
		return false, err
	}

	return eligible == 0, nil
}

func (c *Core) notePromotedWaiter(ctx context.Context, testRunID string) {
	if c == nil || testRunID == "" {
		return
	}

	c.RememberPendingPromote(testRunID)
	c.flushPromoteFollowUp(ctx)
}

// RememberPendingPromote records a promoted waiter that still needs
// follow-up. It adds the id without overwriting other pending ids, and
// does not flush, so a deferred Bob-then-Kick can wait until the reverse
// receiver is wired.
func (c *Core) RememberPendingPromote(testRunID string) {
	if c == nil || testRunID == "" {
		return
	}

	c.promoteMu.Lock()
	defer c.promoteMu.Unlock()

	if c.pendingPromoteIDs == nil {
		c.pendingPromoteIDs = map[string]struct{}{}
	}

	c.pendingPromoteIDs[testRunID] = struct{}{}
}

// SetPromoteFollowUp binds the shared after-ExtendToActive follow-up.
// The callback returns true when Bob then Kick were delivered so the
// pending id can be consumed. False keeps that id so a later flush can
// deliver once the Bob materializer is wired.
func (c *Core) SetPromoteFollowUp(fn func(context.Context, string) bool) {
	if c == nil {
		return
	}

	c.promoteMu.Lock()
	defer c.promoteMu.Unlock()

	c.promoteFollowUp = fn
}

// PendingPromoteIDs lists waiters still waiting for a post-promotion
// follow-up, in sorted order. Empty after every follow-up is delivered or
// when none is pending.
func (c *Core) PendingPromoteIDs() []string {
	if c == nil {
		return []string{}
	}

	c.promoteMu.Lock()
	defer c.promoteMu.Unlock()

	return c.pendingPromoteIDsLocked()
}

// LastPromotedID is a compatibility wrapper for callers that still expect
// a single pending id. It returns one pending waiter when any exist, or
// empty after follow-up is delivered or when none is pending.
func (c *Core) LastPromotedID() string {
	ids := c.PendingPromoteIDs()
	if len(ids) == 0 {
		return ""
	}

	return ids[0]
}

// FlushPromoteFollowUp runs the bound follow-up for every CAS-winning
// promotion still pending. A missing hook or empty pending set is a no-op
// so Attach can promote before the handler binds the seam. A delivered
// follow-up removes that id so a later flush cannot replay it. The
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

	if c.pendingPromoteIDs == nil {
		c.pendingPromoteIDs = map[string]struct{}{}
	}

	fn := c.promoteFollowUp
	if fn == nil || len(c.pendingPromoteIDs) == 0 {
		return
	}

	for _, id := range c.pendingPromoteIDsLocked() {
		if fn(ctx, id) {
			delete(c.pendingPromoteIDs, id)
		}
	}
}

func (c *Core) pendingPromoteIDsLocked() []string {
	if c.pendingPromoteIDs == nil {
		c.pendingPromoteIDs = map[string]struct{}{}
	}

	ids := make([]string, 0, len(c.pendingPromoteIDs))
	for id := range c.pendingPromoteIDs {
		ids = append(ids, id)
	}

	slices.Sort(ids)

	return ids
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
