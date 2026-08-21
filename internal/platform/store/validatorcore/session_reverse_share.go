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
	"gorm.io/gorm/clause"
)

const (
	colReverseShareProviderID = "reverse_share_provider_id"
	colStatsWrittenAt         = "stats_written_at"
)

const (
	// ReasonReverseShareTimeout is the terminal reason the stall sweep stamps
	// when the reverse-share wait outlives the inactivity window. It is the
	// only interrupted reason the late flip may recover.
	ReasonReverseShareTimeout = "reverse_share_timeout"

	// ReasonLateReverseShare is the terminal reason stamped by the late flip
	// when a reverse share arrives after the wait already timed out.
	ReasonLateReverseShare = "late_reverse_share"
)

// OpenReverseAwaitingShare moves the active run from capability_exercise to
// reverse_awaiting_share, opening the event-driven wait for the peer's
// reverse share. The guarded UPDATE is the single CAS; a zero-row result
// means the run already moved on and reports ErrStateTransitionMiss.
func (c *Core) OpenReverseAwaitingShare(ctx context.Context, testRunID string) error {
	if c == nil || c.db == nil {
		return errors.New("validatorcore: store is not configured")
	}

	res := c.db.WithContext(ctx).Model(&TestRun{}).
		Where("test_run_id = ? AND is_active = 1 AND state = ?", testRunID, StateCapabilityExercise).
		Updates(map[string]any{
			colState:     StateReverseAwaitingShare,
			colUpdatedAt: time.Now().Unix(),
		})
	if res.Error != nil {
		return fmt.Errorf("validatorcore: open reverse-share wait: %w", res.Error)
	}

	if res.RowsAffected == 0 {
		return ErrStateTransitionMiss
	}

	return nil
}

// FlipLateReverseShareToPass is the two-transaction late flip for a reverse
// share that arrived after the wait timed out. Tx1 is a state-only guarded
// UPDATE matching is_active=0, state=interrupted,
// terminal_reason=reverse_share_timeout and rewriting only state,
// terminal_reason, and updated_at to terminal_pass/late_reverse_share; the
// active singleton is never retaken and finished_at, expires_at, and the
// harvest markers stay untouched. When Tx1 misses, the row is reloaded: an
// already terminal_pass row still runs Tx2 so a crashed stats write recovers,
// while other interrupted reasons, unrecoverable rows, and missing rows are
// evidence-only. Tx2 runs only after Tx1 commits and is the keyed stats
// UPSERT plus the same-host aggregate rebuild; its error is returned so the
// caller can retry, but Tx1 is never rolled back. The boolean reports whether
// the run is terminal_pass after the call (flipped or confirmed).
func (c *Core) FlipLateReverseShareToPass(ctx context.Context, testRunID string) (bool, error) {
	if c == nil || c.db == nil {
		return false, errors.New("validatorcore: store is not configured")
	}

	res := c.db.WithContext(ctx).Model(&TestRun{}).
		Where("test_run_id = ? AND is_active = 0 AND state = ? AND terminal_reason = ?",
			testRunID, StateInterrupted, ReasonReverseShareTimeout).
		Updates(map[string]any{
			colState:          StateTerminalPass,
			colTerminalReason: ReasonLateReverseShare,
			colUpdatedAt:      time.Now().Unix(),
		})
	if res.Error != nil {
		return false, fmt.Errorf("validatorcore: late reverse-share flip: %w", res.Error)
	}

	if res.RowsAffected == 0 {
		var row TestRun

		err := c.db.WithContext(ctx).
			Select(colTestRunID, colState).
			Where("test_run_id = ?", testRunID).
			First(&row).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, nil
		}

		if err != nil {
			return false, fmt.Errorf("validatorcore: reload after late-flip miss: %w", err)
		}

		if row.State != StateTerminalPass {
			return false, nil
		}
	}

	if err := c.upsertTerminalStatsForRun(ctx, testRunID); err != nil {
		return true, err
	}

	return true, nil
}

// RetryTerminalStats re-drives the stats-only write for one terminal run
// through the keyed UPSERT seam and returns its error, so callers that must
// know whether terminal statistics landed (instead of the best-effort release
// path) can propagate the failure. State is never touched.
func (c *Core) RetryTerminalStats(ctx context.Context, testRunID string) error {
	return c.upsertTerminalStatsForRun(ctx, testRunID)
}

// HealMissingTerminalStats re-drives terminal statistics for every eligible
// opted-in terminal run whose stats_written_at marker is still NULL, using
// the same keyed UPSERT seam as the late flip. Eligibility is state plus
// reason: terminal_pass rows, and interrupted rows whose terminal_reason is
// reverse_share_timeout (the one flippable interruption). An interrupted row
// with any other reason is unflippable and is skipped, so a stalled or
// startup-recovered run is never healed into statistics and never graded
// from evidence a late share recorded. The scan uses the partial heal index
// predicate; state-first ordering holds because the scan only matches rows
// already in a terminal state and the seam never rewrites state. The pass is
// best-effort per row: a failed row is logged and the remaining rows still
// heal.
func (c *Core) HealMissingTerminalStats(ctx context.Context) error {
	if c == nil || c.db == nil {
		return errors.New("validatorcore: store is not configured")
	}

	var ids []string

	if err := c.db.WithContext(ctx).Model(&TestRun{}).
		Select(colTestRunID).
		Where(
			"opt_in_stats = 1 AND stats_written_at IS NULL AND "+
				"(state = ? OR (state = ? AND terminal_reason = ?))",
			StateTerminalPass,
			StateInterrupted,
			ReasonReverseShareTimeout,
		).
		Find(&ids).Error; err != nil {
		return fmt.Errorf("validatorcore: list terminal runs missing stats: %w", err)
	}

	for _, id := range ids {
		if err := c.upsertTerminalStatsForRun(ctx, id); err != nil {
			slog.WarnContext(
				ctx,
				"validatorcore: terminal stats heal failed for run",
				"test_run_id",
				id,
				"err",
				err,
			)

			continue
		}
	}

	return nil
}

// StampReverseShareProviderID records the provider id of the reverse share
// that passed the run. The stamp is first-wins: it lands only when the column
// is still NULL, so a retried delivery of the same share and a later
// unrelated share from the same peer both leave the original occupancy
// untouched. Callers invoke it only after the run reached terminal_pass.
func (c *Core) StampReverseShareProviderID(ctx context.Context, testRunID, providerID string) error {
	if c == nil || c.db == nil {
		return errors.New("validatorcore: store is not configured")
	}

	if providerID == "" {
		return errors.New("validatorcore: empty reverse share provider id")
	}

	res := c.db.WithContext(ctx).Model(&TestRun{}).
		Where("test_run_id = ? AND reverse_share_provider_id IS NULL", testRunID).
		Update(colReverseShareProviderID, providerID)
	if res.Error != nil {
		return fmt.Errorf("validatorcore: stamp reverse share provider id: %w", res.Error)
	}

	return nil
}

// upsertTerminalStatsForRun is the stats-only seam shared by the late flip,
// the strict post-release re-drive, and the missing-stats heal scan. One
// transaction upserts the stats_raw row keyed by the session dedup key,
// stamps stats_written_at when still NULL, and rebuilds the same-host
// aggregate from stats_raw, so repeats never double-count. Every caller runs
// after the release path already consumed the in-memory overlay, so the
// snapshot rebuilds from the persisted row and the evidence log only; the
// upsert keeps previously written grade and platform values when the fresh
// snapshot carries none.
func (c *Core) upsertTerminalStatsForRun(ctx context.Context, testRunID string) error {
	if c == nil || c.db == nil {
		return errors.New("validatorcore: store is not configured")
	}

	row, err := c.GetTestRun(ctx, testRunID)
	if err != nil {
		return fmt.Errorf("validatorcore: load test run for stats upsert: %w", err)
	}

	if !row.OptInStats {
		return nil
	}

	if row.FinishedAt == nil {
		return errors.New("validatorcore: terminal stats require finished_at")
	}

	hostHash, err := c.hashHostForTestRun(row)
	if err != nil {
		return fmt.Errorf("validatorcore: hash target host: %w", err)
	}

	k, err := c.statsHasher.HashStatsK(testRunID)
	if err != nil {
		return fmt.Errorf("validatorcore: stats row key: %w", err)
	}

	snap := statsSnapshotFromTestRun(row, hostHash, *row.FinishedAt, nil)

	err = c.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if gradeErr := fillSnapshotGradesFromEvidence(tx, testRunID, &snap); gradeErr != nil {
			return fmt.Errorf("validatorcore: load evidence grades: %w", gradeErr)
		}

		raw := snap.ToStatsRaw()
		raw.K = k

		if upsertErr := upsertStatsRaw(tx, &raw); upsertErr != nil {
			return fmt.Errorf("validatorcore: upsert stats_raw: %w", upsertErr)
		}

		res := tx.Exec(
			"UPDATE test_run SET stats_written_at = ? "+
				"WHERE test_run_id = ? AND opt_in_stats = 1 AND stats_written_at IS NULL",
			time.Now().Unix(), testRunID,
		)
		if res.Error != nil {
			return fmt.Errorf("validatorcore: stamp stats_written_at: %w", res.Error)
		}

		if rebuildErr := rebuildStatsAggregateForHost(tx, hostHash); rebuildErr != nil {
			return fmt.Errorf("validatorcore: rebuild stats aggregate: %w", rebuildErr)
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("validatorcore: upsert terminal stats writes: %w", err)
	}

	return nil
}

// upsertStatsRaw inserts the stats_raw row or, on a dedup-key conflict,
// revises the existing row in place. Revision never erases previously written
// nullable values: grade and window bucket columns keep the stored value when
// the incoming snapshot has none, platform and api_version keep the stored
// value when the incoming one is empty, and reverse_invite_exercised stays
// true once set. created_at is insert-only so the row keeps its original
// finished_at anchor.
func upsertStatsRaw(tx *gorm.DB, row *StatsRaw) error {
	if row == nil {
		return errors.New("validatorcore: nil stats row")
	}

	keepWhenNull := func(column string) clause.Assignment {
		return clause.Assignment{
			Column: clause.Column{Name: column},
			Value:  gorm.Expr("COALESCE(excluded." + column + ", " + column + ")"),
		}
	}

	keepWhenEmpty := func(column string) clause.Assignment {
		return clause.Assignment{
			Column: clause.Column{Name: column},
			Value:  gorm.Expr("COALESCE(NULLIF(excluded." + column + ", ''), " + column + ")"),
		}
	}

	res := tx.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "k"}},
		DoUpdates: clause.Set([]clause.Assignment{
			{Column: clause.Column{Name: "host_hash"}, Value: gorm.Expr("excluded.host_hash")},
			{Column: clause.Column{Name: "session_kind"}, Value: gorm.Expr("excluded.session_kind")},
			{
				Column: clause.Column{Name: "reverse_invite_exercised"},
				Value:  gorm.Expr("MAX(reverse_invite_exercised, excluded.reverse_invite_exercised)"),
			},
			keepWhenEmpty("platform"),
			keepWhenEmpty("api_version"),
			keepWhenNull("grade_discovery"),
			keepWhenNull("grade_tls"),
			keepWhenNull("grade_jwks"),
			keepWhenNull("grade_httpsig"),
			keepWhenNull("grade_sharing"),
			keepWhenNull("grade_notification"),
			keepWhenNull("grade_token"),
			keepWhenNull("grade_capability"),
			keepWhenNull("window_bucket"),
		}),
	}).Create(row)
	if res.Error != nil {
		return res.Error
	}

	return nil
}
