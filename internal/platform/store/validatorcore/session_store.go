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

// TerminalUpdate carries fields written on a terminal transition.
type TerminalUpdate struct {
	State          string
	SessionKind    string
	TerminalReason string
	OverallGrade   *string
	FinishedAt     int64
}

// GetTestRun loads one test_run row by primary key.
func (c *Core) GetTestRun(ctx context.Context, testRunID string) (*TestRun, error) {
	if c == nil || c.db == nil {
		return nil, errors.New("validatorcore: store is not configured")
	}

	var row TestRun

	err := c.db.WithContext(ctx).First(&row, "test_run_id = ?", testRunID).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrSessionNotFound
		}

		return nil, err
	}

	return &row, nil
}

// CountInFlightPassive returns passive in-flight sessions (created or passive_running).
func (c *Core) CountInFlightPassive(ctx context.Context) (int64, error) {
	if c == nil || c.db == nil {
		return 0, errors.New("validatorcore: store is not configured")
	}

	var count int64

	err := c.db.WithContext(ctx).Model(&TestRun{}).
		Where("is_active = 0 AND state IN ?", []string{StateCreated, StatePassiveRunning}).
		Count(&count).Error
	if err != nil {
		return 0, err
	}

	return count, nil
}

// CreatePassiveSession inserts a passive-core session without taking the active lock.
func (c *Core) CreatePassiveSession(ctx context.Context, row *TestRun) error {
	if c == nil || c.db == nil {
		return errors.New("validatorcore: store is not configured")
	}

	if row == nil {
		return errors.New("validatorcore: nil test run")
	}

	cfg := c.SessionConfig()

	err := c.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var count int64
		if countErr := tx.Model(&TestRun{}).
			Where("is_active = 0 AND state IN ?", []string{StateCreated, StatePassiveRunning}).
			Count(&count).Error; countErr != nil {
			return countErr
		}

		if count >= int64(cfg.InFlightPassiveLimit) {
			return ErrInFlightPassiveLimit
		}

		if createErr := tx.Create(row).Error; createErr != nil {
			return NewStoreError(OpCreateSessionInsert, createErr)
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("validatorcore: create passive session: %w", err)
	}

	return nil
}

// ExtendToActive promotes a passive_complete session to the one-active-run lock.
func (c *Core) ExtendToActive(ctx context.Context, testRunID string) error {
	if c == nil || c.db == nil {
		return errors.New("validatorcore: store is not configured")
	}

	now := time.Now().Unix()

	err := c.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		res := tx.Model(&TestRun{}).
			Where("test_run_id = ? AND is_active = 0 AND state = ?", testRunID, StatePassiveComplete).
			Updates(map[string]any{
				"is_active":    true,
				colState:       StateActiveRunning,
				colSessionKind: SessionKindActiveFull,
				colUpdatedAt:   now,
			})
		if res.Error != nil {
			if errors.Is(res.Error, gorm.ErrDuplicatedKey) {
				return NewStoreError(OpExtendUpdate, res.Error)
			}

			return res.Error
		}

		if res.RowsAffected == 0 {
			var row TestRun

			loadErr := tx.First(&row, "test_run_id = ?", testRunID).Error
			if errors.Is(loadErr, gorm.ErrRecordNotFound) {
				return ErrSessionNotFound
			}

			if loadErr != nil {
				return loadErr
			}

			if row.IsActive {
				return ErrInteractiveRunInProgress
			}

			if row.State == StateCreated || row.State == StatePassiveRunning {
				return ErrSessionNotReady
			}

			return ErrSessionNotReady
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("validatorcore: extend to active: %w", err)
	}

	return nil
}

// TransitionState performs a guarded state update for passive sessions.
func (c *Core) TransitionState(
	ctx context.Context,
	testRunID string,
	expectedIsActive bool,
	expectedState, newState string,
) error {
	if c == nil || c.db == nil {
		return errors.New("validatorcore: store is not configured")
	}

	now := time.Now().Unix()
	isActive := boolToInt(expectedIsActive)

	res := c.db.WithContext(ctx).Model(&TestRun{}).
		Where("test_run_id = ? AND is_active = ? AND state = ?", testRunID, isActive, expectedState).
		Updates(map[string]any{
			colState:     newState,
			colUpdatedAt: now,
		})
	if res.Error != nil {
		return res.Error
	}

	if res.RowsAffected == 0 {
		return ErrStateTransitionMiss
	}

	return nil
}

// EnterTerminalState terminalizes a passive session with is_active=0 guard.
func (c *Core) EnterTerminalState(
	ctx context.Context,
	testRunID string,
	expectedIsActive bool,
	expectedState string,
	update TerminalUpdate,
) error {
	if c == nil || c.db == nil {
		return errors.New("validatorcore: store is not configured")
	}

	if update.SessionKind == "" {
		return errors.New("validatorcore: terminal transition requires session_kind")
	}

	isActive := boolToInt(expectedIsActive)
	reason := update.TerminalReason

	res := c.db.WithContext(ctx).Model(&TestRun{}).
		Where("test_run_id = ? AND is_active = ? AND state = ?", testRunID, isActive, expectedState).
		Updates(map[string]any{
			colState:          update.State,
			colSessionKind:    update.SessionKind,
			colTerminalReason: reason,
			"overall_grade":   update.OverallGrade,
			colFinishedAt:     update.FinishedAt,
			colUpdatedAt:      update.FinishedAt,
		})
	if res.Error != nil {
		return res.Error
	}

	if res.RowsAffected == 0 {
		return ErrStateTransitionMiss
	}

	if isTerminalState(update.State) {
		bestEffortPersistTerminalStats(c, ctx, testRunID)
	}

	return nil
}

// RunStartProbe transitions created -> passive_running for a passive session.
func (c *Core) RunStartProbe(ctx context.Context, testRunID string) error {
	return c.TransitionState(ctx, testRunID, false, StateCreated, StatePassiveRunning)
}

// CompletePassiveProbe transitions passive_running -> passive_complete.
func (c *Core) CompletePassiveProbe(ctx context.Context, testRunID string) error {
	return c.TransitionState(ctx, testRunID, false, StatePassiveRunning, StatePassiveComplete)
}

// FailRunTerminal transitions a passive created session directly to terminal_fail.
func (c *Core) FailRunTerminal(ctx context.Context, testRunID, reason string) error {
	now := time.Now().Unix()

	return c.EnterTerminalState(ctx, testRunID, false, StateCreated, TerminalUpdate{
		State:          StateTerminalFail,
		SessionKind:    SessionKindPassiveOnly,
		TerminalReason: reason,
		FinishedAt:     now,
	})
}

// FailPassiveRunningTerminal terminalizes a passive_running session as fail.
func (c *Core) FailPassiveRunningTerminal(ctx context.Context, testRunID, reason string) error {
	now := time.Now().Unix()

	return c.EnterTerminalState(ctx, testRunID, false, StatePassiveRunning, TerminalUpdate{
		State:          StateTerminalFail,
		SessionKind:    SessionKindPassiveOnly,
		TerminalReason: reason,
		FinishedAt:     now,
	})
}

// StopPassiveComplete terminalizes a passive_complete core-only session on stop.
func (c *Core) StopPassiveComplete(ctx context.Context, testRunID string) error {
	now := time.Now().Unix()
	pass := GradePass

	return c.EnterTerminalState(ctx, testRunID, false, StatePassiveComplete, TerminalUpdate{
		State:          StateTerminalPass,
		SessionKind:    SessionKindPassiveOnly,
		TerminalReason: "stopped",
		OverallGrade:   &pass,
		FinishedAt:     now,
	})
}

// harvestReasonRetentionExpired is the harvest_reason stamped on test_run
// rows tombstoned by retention pruning.
const harvestReasonRetentionExpired = "retention_expired"

// PruneTerminalSessions tombstones terminal test_run rows older than
// retentionDays; the parent row is never deleted. Child rows in
// report_exchange, evidence_row, dispatch_reservation, and share_correlation
// are harvested first, then harvested_at and harvest_reason are stamped and
// is_active is cleared. ON DELETE RESTRICT on the child foreign keys prevents
// accidental evidence erasure. Already-tombstoned rows are excluded so a
// repeat run never re-stamps harvested_at or harvest_reason.
func (c *Core) PruneTerminalSessions(ctx context.Context, retentionDays int) error {
	if c == nil || c.db == nil {
		return errors.New("validatorcore: store is not configured")
	}

	if retentionDays <= 0 {
		return nil
	}

	cutoff := time.Now().Add(-time.Duration(retentionDays) * 24 * time.Hour).Unix()
	now := time.Now().Unix()

	err := c.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		ids := []string{}

		if err := tx.Model(&TestRun{}).
			Where(
				"state IN ? AND finished_at IS NOT NULL AND finished_at < ? AND harvested_at IS NULL",
				[]string{StateTerminalPass, StateTerminalFail},
				cutoff,
			).
			Pluck(colTestRunID, &ids).Error; err != nil {
			return err
		}

		for _, id := range ids {
			if err := harvestRunChildren(tx, id); err != nil {
				return err
			}

			// Raw SQL keeps updated_at untouched: a GORM Updates call would
			// auto-stamp the UpdatedAt field and break the tombstone contract.
			res := tx.Exec(
				"UPDATE test_run SET harvested_at = ?, harvest_reason = ?, is_active = 0 WHERE test_run_id = ?",
				now,
				harvestReasonRetentionExpired,
				id,
			)
			if res.Error != nil {
				return res.Error
			}
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("validatorcore: prune terminal sessions: %w", err)
	}

	return nil
}

// harvestRunChildren deletes the validator-owned child rows of one test run.
// report_exchange goes first so evidence_row.exchange_id ON DELETE SET NULL
// fires before the evidence rows themselves are removed.
func harvestRunChildren(tx *gorm.DB, testRunID string) error {
	models := []any{
		&ReportExchange{},
		&EvidenceRow{},
		&DispatchReservation{},
		&ShareCorrelation{},
	}

	for _, model := range models {
		if err := tx.Where("test_run_id = ?", testRunID).Delete(model).Error; err != nil {
			return err
		}
	}

	return nil
}

func boolToInt(v bool) int {
	if v {
		return 1
	}

	return 0
}
