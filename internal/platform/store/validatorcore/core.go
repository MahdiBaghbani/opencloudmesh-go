// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// Package validatorcore holds federation validator session and statistics
// persistence models and store methods.
package validatorcore

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"gorm.io/gorm"
)

// Core provides federation validator persistence on a shared GORM handle.
type Core struct {
	db                     *gorm.DB
	sessionCfg             SessionConfig
	statsHasher            StatsHostHasher
	sessionContrib         sync.Map
	terminalStatsSnapshots sync.Map
}

// NewCore wraps an existing GORM DB handle for validator persistence.
func NewCore(db *gorm.DB) *Core {
	return &Core{db: db}
}

// DB exposes the underlying GORM handle for tests.
func (c *Core) DB() *gorm.DB {
	if c == nil {
		return nil
	}

	return c.db
}

// MigrateModels runs AutoMigrate for all validator persistence models.
func MigrateModels(db *gorm.DB) error {
	if db == nil {
		return errors.New("validatorcore: nil db")
	}

	if err := db.AutoMigrate(
		&TestRun{},
		&ShareCorrelation{},
		&StatsRaw{},
		&StatsAggregate{},
	); err != nil {
		return fmt.Errorf("validatorcore: migrate: %w", err)
	}

	return nil
}

// FindActiveCorrelation returns the test_run_id for a confirmed correlation on
// the active session. Pending rows are excluded.
func (c *Core) FindActiveCorrelation(
	ctx context.Context,
	role, senderHost, providerID string,
) (string, error) {
	if c == nil || c.db == nil {
		return "", errors.New("validatorcore: store is not configured")
	}

	var row ShareCorrelation

	res := c.db.WithContext(ctx).Raw(`
		SELECT sc.test_run_id FROM share_correlation sc
		INNER JOIN test_run tr ON tr.test_run_id = sc.test_run_id
		WHERE tr.is_active = 1 AND sc.role = ?
		  AND sc.sender_host = ? AND sc.provider_id = ?
		  AND sc.status = 'confirmed'`,
		role, senderHost, providerID,
	).Scan(&row)
	if res.Error != nil {
		return "", res.Error
	}

	if res.RowsAffected == 0 {
		return "", gorm.ErrRecordNotFound
	}

	return row.TestRunID, nil
}

// FindCorrelationAnyStatus returns the test_run_id for an active correlation
// regardless of status. Intended for pending-inclusive confirm-hook use only.
func (c *Core) FindCorrelationAnyStatus(
	ctx context.Context,
	role, senderHost, providerID string,
) (string, error) {
	if c == nil || c.db == nil {
		return "", errors.New("validatorcore: store is not configured")
	}

	var row ShareCorrelation

	res := c.db.WithContext(ctx).Raw(`
		SELECT sc.test_run_id FROM share_correlation sc
		INNER JOIN test_run tr ON tr.test_run_id = sc.test_run_id
		WHERE tr.is_active = 1 AND sc.role = ?
		  AND sc.sender_host = ? AND sc.provider_id = ?`,
		role, senderHost, providerID,
	).Scan(&row)
	if res.Error != nil {
		return "", res.Error
	}

	if res.RowsAffected == 0 {
		return "", gorm.ErrRecordNotFound
	}

	return row.TestRunID, nil
}

// InsertStatsRaw appends one stats_raw row.
func (c *Core) InsertStatsRaw(ctx context.Context, row *StatsRaw) error {
	if c == nil || c.db == nil {
		return errors.New("validatorcore: store is not configured")
	}

	return insertStatsRawDB(c.db.WithContext(ctx), row)
}

// IncrementStatsAggregate upserts aggregate counters for host_hash from one
// stats_raw snapshot. Health is derived from grade columns via DeriveHealthy;
// callers must not supply a separate healthy flag. INSERT ... ON CONFLICT DO
// UPDATE increments counters always; first_seen_ts keeps the earliest timestamp;
// last_platform, last_healthy, and last_seen_ts are replaced only when
// raw.CreatedAt is at least as new as the stored last_seen_ts.
func (c *Core) IncrementStatsAggregate(ctx context.Context, raw *StatsRaw) error {
	if c == nil || c.db == nil {
		return errors.New("validatorcore: store is not configured")
	}

	return incrementStatsAggregateDB(c.db.WithContext(ctx), raw)
}

// PruneStats deletes stats_raw rows older than retentionDays when
// retentionDays > 0, then rebuilds stats_aggregate from remaining stats_raw.
// When retentionDays is 0, no rows are deleted and the aggregate is rebuilt
// from all stats_raw (all-time rebuild).
func (c *Core) PruneStats(ctx context.Context, retentionDays int) error {
	if c == nil || c.db == nil {
		return errors.New("validatorcore: store is not configured")
	}

	err := c.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if retentionDays > 0 {
			cutoff := time.Now().Add(-time.Duration(retentionDays) * 24 * time.Hour).Unix()

			if err := tx.Where("created_at < ?", cutoff).Delete(&StatsRaw{}).Error; err != nil {
				return fmt.Errorf("validatorcore: delete stats_raw: %w", err)
			}
		}

		if err := rebuildStatsAggregate(tx); err != nil {
			return fmt.Errorf("validatorcore: rebuild stats aggregate: %w", err)
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("validatorcore: prune stats: %w", err)
	}

	return nil
}

func rebuildStatsAggregate(tx *gorm.DB) error {
	if err := tx.Where("1 = 1").Delete(&StatsAggregate{}).Error; err != nil {
		return err
	}

	var rawRows []StatsRaw
	if err := tx.Order("host_hash ASC, created_at ASC, id ASC").Find(&rawRows).Error; err != nil {
		return err
	}

	if len(rawRows) == 0 {
		return nil
	}

	byHost := make(map[string]*StatsAggregate)
	latestRaw := make(map[string]StatsRaw)

	for _, row := range rawRows {
		agg, ok := byHost[row.HostHash]
		if !ok {
			agg = &StatsAggregate{
				HostHash:    row.HostHash,
				FirstSeenTS: row.CreatedAt,
			}
			byHost[row.HostHash] = agg
		}

		agg.TotalSessions++

		if DeriveHealthy(row) {
			agg.HealthySessions++
		}

		if row.CreatedAt < agg.FirstSeenTS || agg.FirstSeenTS == 0 {
			agg.FirstSeenTS = row.CreatedAt
		}

		if row.CreatedAt >= agg.LastSeenTS {
			agg.LastSeenTS = row.CreatedAt
			latestRaw[row.HostHash] = row
		}
	}

	for hostHash, agg := range byHost {
		latest := latestRaw[hostHash]
		agg.LastPlatform = latest.Platform
		agg.LastHealthy = DeriveHealthy(latest)

		if err := tx.Create(agg).Error; err != nil {
			return err
		}
	}

	return nil
}

func insertStatsRawDB(db *gorm.DB, row *StatsRaw) error {
	if row == nil {
		return errors.New("validatorcore: nil stats row")
	}

	if err := db.Create(row).Error; err != nil {
		return err
	}

	return nil
}

func incrementStatsAggregateDB(db *gorm.DB, raw *StatsRaw) error {
	if raw == nil {
		return errors.New("validatorcore: nil stats row")
	}

	if raw.HostHash == "" {
		return errors.New("validatorcore: empty host hash")
	}

	healthy := DeriveHealthy(*raw)

	healthyInc := int64(0)
	if healthy {
		healthyInc = 1
	}

	lastHealthy := 0
	if healthy {
		lastHealthy = 1
	}

	return db.Exec(`
		INSERT INTO stats_aggregate (
			host_hash, total_sessions, healthy_sessions,
			last_platform, last_healthy, first_seen_ts, last_seen_ts
		) VALUES (?, 1, ?, ?, ?, ?, ?)
		ON CONFLICT(host_hash) DO UPDATE SET
			total_sessions = stats_aggregate.total_sessions + 1,
			healthy_sessions = stats_aggregate.healthy_sessions + excluded.healthy_sessions,
			first_seen_ts = CASE
				WHEN stats_aggregate.first_seen_ts = 0 THEN excluded.first_seen_ts
				WHEN excluded.first_seen_ts < stats_aggregate.first_seen_ts
				THEN excluded.first_seen_ts
				ELSE stats_aggregate.first_seen_ts
			END,
			last_platform = CASE
				WHEN excluded.last_seen_ts >= stats_aggregate.last_seen_ts
				THEN excluded.last_platform
				ELSE stats_aggregate.last_platform
			END,
			last_healthy = CASE
				WHEN excluded.last_seen_ts >= stats_aggregate.last_seen_ts
				THEN excluded.last_healthy
				ELSE stats_aggregate.last_healthy
			END,
			last_seen_ts = CASE
				WHEN excluded.last_seen_ts >= stats_aggregate.last_seen_ts
				THEN excluded.last_seen_ts
				ELSE stats_aggregate.last_seen_ts
			END`,
		raw.HostHash,
		healthyInc,
		raw.Platform,
		lastHealthy,
		raw.CreatedAt,
		raw.CreatedAt,
	).Error
}

func (c *Core) insertStatsRawAndAggregate(ctx context.Context, raw *StatsRaw) error {
	if c == nil || c.db == nil {
		return errors.New("validatorcore: store is not configured")
	}

	err := c.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := insertStatsRawDB(tx, raw); err != nil {
			return fmt.Errorf("validatorcore: insert stats_raw: %w", err)
		}

		if err := incrementStatsAggregateDB(tx, raw); err != nil {
			return fmt.Errorf("validatorcore: increment stats_aggregate: %w", err)
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("validatorcore: persist terminal stats writes: %w", err)
	}

	return nil
}
