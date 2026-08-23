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
	db          *gorm.DB
	sessionCfg  SessionConfig
	statsHasher StatsHostHasher
	// claimPayloadLoadHook is a test seam invoked while loading the
	// outgoing invite row inside the claim transaction. Production
	// leaves it nil. A non-nil error aborts the transaction so
	// s1_claimed_at is not written.
	claimPayloadLoadHook func() error
	// promoteAfterSelectHook is a test seam invoked after a ready
	// waiter is selected and before ExtendToActive CASes it.
	// Production leaves it nil.
	promoteAfterSelectHook func(testRunID string)
	// promoteMu guards lastPromotedID and promoteFollowUp. Startup
	// promotion, probe promotion, and a late reverse-receiver bind
	// all touch that pending follow-up state.
	promoteMu sync.Mutex
	// promoteFollowUp is the shared after-ExtendToActive follow-up
	// (Bob materialization + Kick). The passive handler binds it.
	// It returns true when the follow-up was delivered so the pending
	// id can be consumed. False defers until the next flush. Nil is a
	// no-op so Attach can promote before the handler exists.
	promoteFollowUp func(ctx context.Context, testRunID string) bool
	// lastPromotedID is the test_run_id last promoted by a CAS
	// winner that still needs follow-up. Cleared after a successful
	// delivery. Empty means none is pending.
	lastPromotedID string
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
// retentionDays > 0. When retentionDays is 0, no rows are deleted.
func (c *Core) PruneStats(ctx context.Context, retentionDays int) error {
	if c == nil || c.db == nil {
		return errors.New("validatorcore: store is not configured")
	}

	if retentionDays <= 0 {
		return nil
	}

	cutoff := time.Now().Add(-time.Duration(retentionDays) * 24 * time.Hour).Unix()
	if err := c.db.WithContext(ctx).Where("created_at < ?", cutoff).Delete(&StatsRaw{}).Error; err != nil {
		return fmt.Errorf("validatorcore: prune stats: %w", err)
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
