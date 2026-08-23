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

		query := c.db.WithContext(ctx).Model(&TestRun{}).
			Where("is_active = 0 AND state = ? AND updated_at < ?", item.state, cutoff)

		if item.state == StatePassiveRunning {
			query = query.Where("NOT (opt_in_active = 1 AND passive_ready_at IS NOT NULL)")
		}

		var ids []string
		if err := query.Pluck("test_run_id", &ids).Error; err != nil {
			return fmt.Errorf("list expired %s sessions: %w", item.state, err)
		}

		for _, id := range ids {
			if err := c.failPassiveTTL(ctx, id, item.state, item.reason); err != nil {
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
		if err := c.failPassiveTTL(ctx, id, StatePassiveComplete, "passive_complete_ttl_expired"); err != nil {
			return err
		}
	}

	return nil
}

func (c *Core) failPassiveTTL(ctx context.Context, testRunID, expectedState, reason string) error {
	err := c.FailPassive(ctx, testRunID, expectedState, reason)
	if err == nil || errors.Is(err, ErrStateTransitionMiss) {
		return nil
	}

	return err
}
