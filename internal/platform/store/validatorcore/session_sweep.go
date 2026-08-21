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

func (c *Core) sweepPassiveInFlightTTL(ctx context.Context) error {
	cfg := c.SessionConfig()
	now := time.Now().Unix()

	states := []struct {
		state      string
		ttlSeconds int
		reason     string
	}{
		{StateCreated, cfg.CreatedTTLSeconds, "created_ttl_expired"},
		{StatePassiveRunning, cfg.PassiveRunningTTLSeconds, "passive_running_ttl_expired"},
	}

	for _, item := range states {
		if item.ttlSeconds <= 0 {
			continue
		}

		cutoff := now - int64(item.ttlSeconds)

		var ids []string
		if err := c.db.WithContext(ctx).Model(&TestRun{}).
			Where("is_active = 0 AND state = ? AND updated_at < ?", item.state, cutoff).
			Pluck("test_run_id", &ids).Error; err != nil {
			return fmt.Errorf("list expired %s sessions: %w", item.state, err)
		}

		for _, id := range ids {
			if err := c.terminalizePassiveTTL(ctx, id, item.state, item.reason, now); err != nil {
				return err
			}
		}
	}

	return nil
}

func (c *Core) sweepPassiveCompleteTTL(ctx context.Context) error {
	cfg := c.SessionConfig()
	if cfg.PassiveCompleteTTLSeconds <= 0 {
		return nil
	}

	now := time.Now().Unix()
	cutoff := now - int64(cfg.PassiveCompleteTTLSeconds)

	var ids []string
	if err := c.db.WithContext(ctx).Model(&TestRun{}).
		Where("is_active = 0 AND state = ? AND updated_at < ?", StatePassiveComplete, cutoff).
		Pluck("test_run_id", &ids).Error; err != nil {
		return fmt.Errorf("list expired passive_complete sessions: %w", err)
	}

	for _, id := range ids {
		if err := c.terminalizePassiveTTL(ctx, id, StatePassiveComplete, "passive_complete_ttl_expired", now); err != nil {
			return err
		}
	}

	return nil
}

func (c *Core) terminalizePassiveTTL(
	ctx context.Context,
	testRunID, expectedState, reason string,
	now int64,
) error {
	var terminalized bool

	err := c.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var row TestRun

		loadErr := tx.Where(
			"test_run_id = ? AND is_active = 0 AND state = ?",
			testRunID,
			expectedState,
		).First(&row).Error
		if errors.Is(loadErr, gorm.ErrRecordNotFound) {
			return nil
		}

		if loadErr != nil {
			return loadErr
		}

		res := tx.Model(&TestRun{}).
			Where("test_run_id = ? AND is_active = 0 AND state = ?", testRunID, expectedState).
			Updates(map[string]any{
				colState:          StateTerminalFail,
				colTerminalReason: reason,
				colFinishedAt:     now,
				colUpdatedAt:      now,
			})
		if res.Error != nil {
			return res.Error
		}

		if res.RowsAffected > 0 {
			terminalized = true
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("validatorcore: terminalize passive ttl: %w", err)
	}

	if terminalized {
		bestEffortPersistTerminalStats(c, ctx, testRunID)
	}

	return nil
}
