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
	"gorm.io/gorm/clause"
)

// Core provides federation validator persistence on a shared GORM handle.
type Core struct {
	db                     *gorm.DB
	sessionCfg             SessionConfig
	statsHasher            StatsHostHasher
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

// MigrateModels is a compatibility alias for ApplyValidatorSchema kept for
// existing tests and helpers. The explicit DDL applicator is authoritative;
// no AutoMigrate runs for validator tables.
func MigrateModels(db *gorm.DB) error {
	return ApplyValidatorSchema(db)
}

// InsertStatsRaw appends one stats_raw row.
func (c *Core) InsertStatsRaw(ctx context.Context, row *StatsRaw) error {
	if c == nil || c.db == nil {
		return errors.New("validatorcore: store is not configured")
	}

	return insertStatsRawDB(c.db.WithContext(ctx), row)
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

	byHost := make(map[string][]StatsRaw)

	for _, row := range rawRows {
		byHost[row.HostHash] = append(byHost[row.HostHash], row)
	}

	for hostHash, rows := range byHost {
		if err := tx.Create(aggregateStatsRawForHost(hostHash, rows)).Error; err != nil {
			return err
		}
	}

	return nil
}

// rebuildStatsAggregateForHost recomputes one host's aggregate from all its
// stats_raw rows. The stored row is deleted first so a host with no remaining
// raw rows disappears instead of going stale.
func rebuildStatsAggregateForHost(tx *gorm.DB, hostHash string) error {
	if err := tx.Where("host_hash = ?", hostHash).Delete(&StatsAggregate{}).Error; err != nil {
		return err
	}

	var rawRows []StatsRaw
	if err := tx.Where("host_hash = ?", hostHash).
		Order("created_at ASC, id ASC").
		Find(&rawRows).Error; err != nil {
		return err
	}

	if len(rawRows) == 0 {
		return nil
	}

	return tx.Create(aggregateStatsRawForHost(hostHash, rawRows)).Error
}

// aggregateStatsRawForHost folds one host's raw rows into an aggregate:
// counters are recomputed from scratch, first_seen_ts is the earliest
// created_at, and last_platform/last_healthy/last_seen_ts are last-seen-wins
// with ties broken by row id. rows must be ordered by created_at, id.
func aggregateStatsRawForHost(hostHash string, rows []StatsRaw) *StatsAggregate {
	agg := &StatsAggregate{HostHash: hostHash}

	var latest StatsRaw

	for _, row := range rows {
		agg.TotalSessions++

		if DeriveHealthy(row) {
			agg.HealthySessions++
		}

		if agg.FirstSeenTS == 0 || row.CreatedAt < agg.FirstSeenTS {
			agg.FirstSeenTS = row.CreatedAt
		}

		if row.CreatedAt >= agg.LastSeenTS {
			agg.LastSeenTS = row.CreatedAt
			latest = row
		}
	}

	agg.LastPlatform = latest.Platform
	agg.LastHealthy = DeriveHealthy(latest)

	return agg
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

// insertStatsRawOrIgnore inserts one stats_raw row, treating a conflict on
// the dedup key k as a no-op, and reports whether a row was actually inserted.
func insertStatsRawOrIgnore(tx *gorm.DB, row *StatsRaw) (bool, error) {
	if row == nil {
		return false, errors.New("validatorcore: nil stats row")
	}

	res := tx.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "k"}},
		DoNothing: true,
	}).Create(row)
	if res.Error != nil {
		return false, res.Error
	}

	return res.RowsAffected > 0, nil
}
