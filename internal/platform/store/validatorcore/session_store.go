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

// TerminalUpdate carries fields written on a terminal transition.
type TerminalUpdate struct {
	State          string
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

// ExtendToActive promotes a passive_complete session to the one-active-run
// lock. The CAS is is_active 0->1 only; bob_user_id is minted in the same
// transaction so the identity is never a later write.
func (c *Core) ExtendToActive(ctx context.Context, testRunID string) error {
	if c == nil || c.db == nil {
		return errors.New("validatorcore: store is not configured")
	}

	now := time.Now().Unix()

	err := c.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		bobID, mintErr := uuid.NewV7()
		if mintErr != nil {
			return fmt.Errorf("validatorcore: mint bob user id: %w", mintErr)
		}

		res := tx.Model(&TestRun{}).
			Where("test_run_id = ? AND is_active = 0 AND state = ?", testRunID, StatePassiveComplete).
			Updates(map[string]any{
				colIsActive:  true,
				colState:     StateActiveRunning,
				colBobUserID: bobID.String(),
				colUpdatedAt: now,
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

	isActive := boolToInt(expectedIsActive)
	reason := update.TerminalReason

	res := c.db.WithContext(ctx).Model(&TestRun{}).
		Where("test_run_id = ? AND is_active = ? AND state = ?", testRunID, isActive, expectedState).
		Updates(map[string]any{
			colState:          update.State,
			colTerminalReason: reason,
			colOverallGrade:   update.OverallGrade,
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

// RecordPassiveProbeFacts writes discovery-derived platform and API version
// onto the run and, when a TLS grade is present, a first-wins passive TLS
// evidence row. Terminal stats later read these persisted fields and rows.
func (c *Core) RecordPassiveProbeFacts(
	ctx context.Context,
	testRunID string,
	platform, apiVersion string,
	tlsGrade *string,
) error {
	if c == nil || c.db == nil {
		return errors.New("validatorcore: store is not configured")
	}

	if testRunID == "" {
		return errors.New("validatorcore: empty test run id")
	}

	now := time.Now().Unix()
	updates := map[string]any{
		colUpdatedAt: now,
	}

	if platform != "" {
		updates["platform"] = platform
	}

	if apiVersion != "" {
		updates["api_version"] = apiVersion
	}

	if len(updates) > 1 {
		if err := c.db.WithContext(ctx).Model(&TestRun{}).
			Where("test_run_id = ?", testRunID).
			Updates(updates).Error; err != nil {
			return fmt.Errorf("validatorcore: record passive probe facts: %w", err)
		}
	}

	if tlsGrade == nil || *tlsGrade == "" {
		return nil
	}

	return c.ApplyEvidenceFact(ctx, ApplyEvidenceFactInput{
		TestRunID:    testRunID,
		Area:         SpecificationAreaTLS,
		Step:         "handshake",
		ReasonCode:   "tls_probed",
		Severity:     *tlsGrade,
		AffectsGrade: true,
		Leg:          evidenceLegPassive,
	})
}

// FailRunTerminal transitions a passive created session directly to terminal_fail.
func (c *Core) FailRunTerminal(ctx context.Context, testRunID, reason string) error {
	now := time.Now().Unix()

	return c.EnterTerminalState(ctx, testRunID, false, StateCreated, TerminalUpdate{
		State:          StateTerminalFail,
		TerminalReason: reason,
		FinishedAt:     now,
	})
}

// FailPassiveRunningTerminal terminalizes a passive_running session as fail.
func (c *Core) FailPassiveRunningTerminal(ctx context.Context, testRunID, reason string) error {
	now := time.Now().Unix()

	return c.EnterTerminalState(ctx, testRunID, false, StatePassiveRunning, TerminalUpdate{
		State:          StateTerminalFail,
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
		TerminalReason: "stopped",
		OverallGrade:   &pass,
		FinishedAt:     now,
	})
}

// harvestReasonRetentionExpired is the harvest_reason stamped on permanent
// test_run rows tombstoned by the retention sweep. Non-permanent pass and
// fail rows are hard-deleted children first, then parent; only permanent
// rows are tombstoned, and only by that sweep.
const harvestReasonRetentionExpired = HarvestReasonExpired

// PruneTerminalSessions applies retention to aged non-permanent pass and
// fail rows. Interrupted rows stay so a later resume or flip can still find
// them. opt_in_permanent=1 rows are skipped so durable reports survive the
// default window. Already-harvested rows, nonterminal rows, is_active=1
// rows, and rows newer than the cutoff are excluded. Child rows are
// harvested first (RESTRICT FKs), then the parent test_run is hard-deleted.
func (c *Core) PruneTerminalSessions(ctx context.Context, retentionDays int) error {
	if c == nil || c.db == nil {
		return errors.New("validatorcore: store is not configured")
	}

	if retentionDays <= 0 {
		return nil
	}

	cutoff := time.Now().Add(-time.Duration(retentionDays) * 24 * time.Hour).Unix()

	err := c.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		rows := []TestRun{}

		if err := tx.Model(&TestRun{}).
			Where(
				"state IN ? AND finished_at IS NOT NULL AND finished_at < ? "+
					"AND harvested_at IS NULL AND opt_in_permanent = 0 AND is_active = 0",
				prunableTerminalStateSet(),
				cutoff,
			).
			Select(colTestRunID).
			Find(&rows).Error; err != nil {
			return err
		}

		for _, row := range rows {
			if err := pruneAgedNonPermanentRun(tx, row.TestRunID); err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("validatorcore: prune terminal sessions: %w", err)
	}

	return nil
}

func pruneAgedNonPermanentRun(tx *gorm.DB, id string) error {
	if err := harvestRunChildren(tx, id); err != nil {
		return err
	}

	return tx.Where("test_run_id = ?", id).Delete(&TestRun{}).Error
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
