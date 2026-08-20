// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"
)

// Attach wraps an existing GORM handle (for example from sqlitecore), applies
// the explicit validator schema on that handle, then runs startup maintenance.
// Callers outside validator mode must not invoke Attach.
func Attach(db *gorm.DB, cfg SessionConfig) (*Core, error) {
	if db == nil {
		return nil, errors.New("validatorcore: nil db")
	}

	if err := ApplyValidatorSchema(db); err != nil {
		return nil, err
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

	// Terminalize leftover is_active=1 rows before retention so a just-sealed
	// interrupted permanent report gets a future expires_at and is not swept
	// immediately. Empty until that writer is wired.
	c.startupTerminalizeUnrecoverableActive(ctx)

	if err := c.sweepPassiveInFlightTTL(ctx); err != nil {
		return fmt.Errorf("sweep passive in-flight ttl: %w", err)
	}

	if err := c.sweepPassiveCompleteTTL(ctx); err != nil {
		return fmt.Errorf("sweep passive_complete ttl: %w", err)
	}

	if err := c.SweepExpiredPermanentReports(ctx); err != nil {
		return fmt.Errorf("sweep expired permanent reports: %w", err)
	}

	if c.sessionCfg.TerminalRetentionDays > 0 {
		if err := c.pruneTerminalRetention(ctx, c.sessionCfg.TerminalRetentionDays); err != nil {
			return fmt.Errorf("prune terminal retention: %w", err)
		}
	}

	return nil
}

// startupTerminalizeUnrecoverableActive is the startup hook that later
// terminalizes leftover is_active=1 rows as interrupted before retention
// sweeps run. No-op until that writer is wired.
func (c *Core) startupTerminalizeUnrecoverableActive(_ context.Context) {
	if c == nil {
		return
	}
}

// pruneTerminalRetention hard-deletes aged non-permanent terminal test_run
// rows after children-first cleanup, then prunes stats_raw for the same
// retention window and rebuilds stats_aggregate from remaining raw.
// Permanent rows are spared here and tombstoned by the expiry sweep.
// PruneStats stays on stats_raw.created_at only and must not consult
// test_run or delete permanent reports.
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
