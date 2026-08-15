// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	gormsqlite "github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Open opens ocm.db under dataDir with immediate write transactions, migrates
// validator models, and runs startup TTL sweep plus terminal retention prune.
func Open(dataDir string, cfg SessionConfig) (*Core, error) {
	if dataDir == "" {
		return nil, errors.New("validatorcore: data_dir is required")
	}

	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("validatorcore: create data dir: %w", err)
	}

	dbPath := filepath.Join(dataDir, "ocm.db")
	dsn := dbPath + "?_pragma=busy_timeout(5000)&_txlock=immediate"

	db, err := gorm.Open(gormsqlite.Open(dsn), &gorm.Config{
		Logger:         logger.Default.LogMode(logger.Silent),
		TranslateError: true,
	})
	if err != nil {
		return nil, fmt.Errorf("validatorcore: open database: %w", err)
	}

	if err := MigrateModels(db); err != nil {
		return nil, fmt.Errorf("validatorcore: migrate: %w", err)
	}

	core := NewCore(db)
	core.sessionCfg = cfg

	if err := core.startupMaintenance(context.Background()); err != nil {
		return nil, fmt.Errorf("validatorcore: startup maintenance: %w", err)
	}

	return core, nil
}

// Attach wraps an existing GORM handle (for example from sqlitecore) and runs
// startup maintenance. MigrateModels must already have run on the handle.
func Attach(db *gorm.DB, cfg SessionConfig) (*Core, error) {
	if db == nil {
		return nil, errors.New("validatorcore: nil db")
	}

	core := NewCore(db)
	core.sessionCfg = cfg

	if err := core.startupMaintenance(context.Background()); err != nil {
		return nil, fmt.Errorf("validatorcore: startup maintenance: %w", err)
	}

	return core, nil
}

func (c *Core) startupMaintenance(ctx context.Context) error {
	if c == nil || c.db == nil {
		return errors.New("validatorcore: store is not configured")
	}

	if err := c.sweepPassiveInFlightTTL(ctx); err != nil {
		return fmt.Errorf("sweep passive in-flight ttl: %w", err)
	}

	if err := c.sweepPassiveCompleteTTL(ctx); err != nil {
		return fmt.Errorf("sweep passive_complete ttl: %w", err)
	}

	if c.sessionCfg.TerminalRetentionDays > 0 {
		if err := c.pruneTerminalRetention(ctx, c.sessionCfg.TerminalRetentionDays); err != nil {
			return fmt.Errorf("prune terminal retention: %w", err)
		}
	}

	return nil
}

// pruneTerminalRetention deletes aged terminal test_run rows and prunes stats_raw
// for the same retention window, then rebuilds stats_aggregate from remaining raw.
func (c *Core) pruneTerminalRetention(ctx context.Context, retentionDays int) error {
	if retentionDays <= 0 {
		return nil
	}

	if err := c.PruneTerminalSessions(ctx, retentionDays); err != nil {
		return fmt.Errorf("prune terminal sessions: %w", err)
	}

	if err := c.PruneStats(ctx, retentionDays); err != nil {
		return fmt.Errorf("prune stats: %w", err)
	}

	return nil
}

// SessionConfig returns the configured session limits for this store.
func (c *Core) SessionConfig() SessionConfig {
	if c == nil {
		return DefaultSessionConfig()
	}

	if c.sessionCfg.InFlightPassiveLimit == 0 {
		return DefaultSessionConfig()
	}

	return c.sessionCfg
}

// SetSessionConfig overrides session limits for this store handle.
func (c *Core) SetSessionConfig(cfg SessionConfig) {
	if c == nil {
		return
	}

	c.sessionCfg = cfg
}
