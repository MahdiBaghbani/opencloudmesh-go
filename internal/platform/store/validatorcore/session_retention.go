// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"gorm.io/gorm"
)

// RetentionSweepInterval is the store-level cadence for hard expiry. Soft
// expiry is handler-side and does not wait for this ticker.
const RetentionSweepInterval = time.Hour

// SweepExpiredPermanentReports tombstones opted-in pass and fail reports
// whose expires_at has elapsed. Interrupted permanent reports stay live so
// a later flip can resume them. The parent row stays so the report URL
// still resolves; evidence children are deleted and PII columns are wiped.
func (c *Core) SweepExpiredPermanentReports(ctx context.Context) error {
	if c == nil || c.db == nil {
		return errors.New("validatorcore: store is not configured")
	}

	now := time.Now().Unix()
	ids := []string{}

	err := c.db.WithContext(ctx).Model(&TestRun{}).
		Where(
			"opt_in_permanent = 1 AND is_active = 0 AND harvested_at IS NULL "+
				"AND expires_at IS NOT NULL AND expires_at <= ? AND state IN ?",
			now,
			prunableTerminalStateSet(),
		).
		Pluck(colTestRunID, &ids).Error
	if err != nil {
		return fmt.Errorf("validatorcore: list expired permanent reports: %w", err)
	}

	for _, id := range ids {
		if tombstoneErr := c.tombstoneExpiredPermanent(ctx, id, now); tombstoneErr != nil {
			return tombstoneErr
		}
	}

	return nil
}

// tombstoneExpiredPermanent stamps the parent first so a crash after the
// stamp still hides the report, then deletes evidence children. A miss
// (already harvested or still live) is not an error.
func (c *Core) tombstoneExpiredPermanent(ctx context.Context, id string, now int64) error {
	if c == nil || c.db == nil {
		return errors.New("validatorcore: store is not configured")
	}

	err := c.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		res := tx.Model(&TestRun{}).
			Where(
				"test_run_id = ? AND opt_in_permanent = 1 AND is_active = 0 "+
					"AND harvested_at IS NULL AND expires_at IS NOT NULL AND expires_at <= ?",
				id,
				now,
			).
			// outgoing_invite_id is a soft pointer. NULLing it releases
			// idx_test_run_outgoing_invite so a later run can reuse the id.
			// Deleting the peer outgoing_invites product row is left to the
			// prune/tombstone path that owns peer-invite cleanup.
			Updates(map[string]any{
				"harvested_at":               now,
				"harvest_reason":             HarvestReasonExpired,
				colIsActive:                  false,
				colUpdatedAt:                 now,
				"target_origin":              "",
				"target_host":                "",
				"discovery_url":              "",
				"jwks_uri":                   "",
				"manifest_json":              nil,
				colOverallGrade:              nil,
				colStarterOCMID:              nil,
				colS1ClaimedAt:               nil,
				colBobUserID:                 nil,
				colOutgoingInviteID:          nil,
				"reverse_invite_token":       nil,
				"reverse_invite_imported_at": nil,
				"designated_share_with":      nil,
				"reverse_share_provider_id":  nil,
			})
		if res.Error != nil {
			return res.Error
		}

		if res.RowsAffected == 0 {
			return nil
		}

		return harvestRunChildren(tx, id)
	})
	if err != nil {
		return fmt.Errorf("validatorcore: tombstone expired permanent report: %w", err)
	}

	return nil
}

// StartRetentionSweep runs sweepRetentionAndPrune on RetentionSweepInterval
// until ctx is cancelled. Attach already ran one pass; this loop covers a
// long-lived process so aged non-permanent terminal rows are pruned without
// a restart.
func (c *Core) StartRetentionSweep(ctx context.Context) {
	c.startRetentionSweep(ctx, RetentionSweepInterval)
}

// startRetentionSweep is the interval-parameterized loop behind
// StartRetentionSweep so tests can run the ticker on a short cadence.
func (c *Core) startRetentionSweep(ctx context.Context, interval time.Duration) {
	if c == nil || ctx == nil {
		return
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := c.sweepRetentionAndPrune(ctx); err != nil {
				slog.WarnContext(
					ctx,
					"validatorcore: retention sweep failed",
					"err",
					err,
				)

				continue
			}
		}
	}
}
