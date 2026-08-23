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
	"sync"

	"gorm.io/gorm"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/appctx"
)

// Attach wraps an existing GORM handle (for example from sqlitecore), applies
// the explicit validator schema on that handle, then runs startup maintenance.
// Callers outside validator mode must not invoke Attach. When startup
// maintenance must heal missing terminal statistics, use
// AttachWithStatsHasher so the hasher is installed before that pass.
func Attach(db *gorm.DB, cfg SessionConfig) (*Core, error) {
	return AttachWithStatsHasher(db, cfg, nil)
}

// AttachWithStatsHasher is Attach plus a stats hasher installed before
// startup maintenance, so missing terminal statistics can be written
// before a later tombstone or prune wipes the origin those writes need.
func AttachWithStatsHasher(db *gorm.DB, cfg SessionConfig, hasher StatsHostHasher) (*Core, error) {
	if db == nil {
		return nil, errors.New("validatorcore: nil db")
	}

	if err := ApplyValidatorSchema(db); err != nil {
		return nil, err
	}

	core := NewCore(db)
	core.sessionCfg = cfg

	if hasher != nil {
		core.SetStatsHostHasher(hasher)
	}

	if err := core.startupMaintenance(context.Background()); err != nil {
		return nil, fmt.Errorf("validatorcore: startup maintenance: %w", err)
	}

	return core, nil
}

func (c *Core) startupMaintenance(ctx context.Context) error {
	if c == nil || c.db == nil {
		return errors.New("validatorcore: store is not configured")
	}

	first := false

	var firstErr error

	startupFirstMaintenanceOnce.Do(func() {
		first = true
		firstErr = c.firstStartupMaintenance(ctx)
	})

	if first {
		return firstErr
	}

	return c.repeatStartupMaintenance(ctx)
}

// startupFirstMaintenanceOnce enforces the process-local first-maintenance
// guard: the first startup maintenance pass in this process runs the two
// one-shot operations (leftover active-row recovery and the stall sweep), and
// later Attach calls skip both, so a run this process legitimately owns is
// never interrupted or swept by a re-attach. The guard is consumed on the
// first attempt even when the pass fails: an Attach error aborts startup, so
// a failed first pass never leaves a running store that skipped its
// one-shots.
var startupFirstMaintenanceOnce sync.Once

// firstStartupMaintenance runs the full startup maintenance chain for the
// first Attach in this process: leftover active-row recovery, ready-waiter
// promotion, the passive TTL sweeps, the stall sweep, the retention sweep,
// and the terminal prune, in that order. Error propagation matches the
// per-step conventions: recovery is best-effort, every later step fails
// the pass.
func (c *Core) firstStartupMaintenance(ctx context.Context) error {
	// Terminalize leftover is_active=1 rows before retention so a just-sealed
	// interrupted permanent report gets a future expires_at and is not swept
	// immediately.
	c.startupTerminalizeUnrecoverableActive(ctx)

	if err := c.PromoteOldestReadyWaiter(ctx); err != nil {
		return fmt.Errorf("promote ready waiter: %w", err)
	}

	c.flushPromoteFollowUp(ctx)

	if err := c.sweepPassiveSessionTTL(ctx); err != nil {
		return err
	}

	if err := c.SweepStalledActiveSessions(ctx); err != nil {
		return fmt.Errorf("sweep stalled active sessions: %w", err)
	}

	return c.sweepRetentionAndPrune(ctx)
}

// repeatStartupMaintenance runs the startup maintenance chain for every
// Attach after the first in this process: ready-waiter promotion, the
// passive TTL sweeps, the retention sweep, and the terminal prune. The
// one-shot recovery and stall passes already ran and must not rerun.
func (c *Core) repeatStartupMaintenance(ctx context.Context) error {
	if err := c.PromoteOldestReadyWaiter(ctx); err != nil {
		return fmt.Errorf("promote ready waiter: %w", err)
	}

	c.flushPromoteFollowUp(ctx)

	if err := c.sweepPassiveSessionTTL(ctx); err != nil {
		return err
	}

	return c.sweepRetentionAndPrune(ctx)
}

func (c *Core) sweepPassiveSessionTTL(ctx context.Context) error {
	if err := c.sweepPassiveInFlightTTL(ctx); err != nil {
		return fmt.Errorf("sweep passive in-flight ttl: %w", err)
	}

	if err := c.sweepPassiveCompleteTTL(ctx); err != nil {
		return fmt.Errorf("sweep passive_complete ttl: %w", err)
	}

	return nil
}

// sweepRetentionAndPrune heals missing terminal statistics first so a later
// tombstone or prune cannot wipe the origin and evidence those writes still
// need, then tombstones expired permanent reports, then hard-deletes aged
// non-permanent pass and fail rows and prunes aged stats_raw. A non-positive
// TerminalRetentionDays skips the terminal and stats prune only; the heal
// and permanent expiry sweep still run.
func (c *Core) sweepRetentionAndPrune(ctx context.Context) error {
	if err := c.HealMissingTerminalStats(ctx); err != nil {
		return fmt.Errorf("heal missing terminal stats: %w", err)
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

// startupRecoveryReason is the terminal_reason stamped on leftover active
// runs interrupted by startup recovery. The reason is unflippable: the run
// belongs to a dead process, so no later transition may rewrite it.
const startupRecoveryReason = "startup_unrecoverable_active"

// startupTerminalizeUnrecoverableActive runs startup recovery for leftover
// is_active=1 rows. The pass is best-effort: a failure is logged and left to
// the stall sweep rather than blocking startup.
func (c *Core) startupTerminalizeUnrecoverableActive(ctx context.Context) {
	if err := c.terminalizeUnrecoverableActiveRuns(ctx); err != nil {
		appctx.GetLogger(ctx).Error(
			"validator startup recovery of leftover active runs failed",
			slog.Any("error", err),
		)
	}
}

// terminalizeUnrecoverableActiveRuns interrupts every row still holding the
// active lock in a non-terminal state. The lock is process-local, so at
// startup such a row belongs to a previous process that can never finish the
// run. Both the selection and the guarded write exclude the terminal set
// instead of naming non-terminal states, so a leftover row is interrupted
// under whatever non-terminal name it holds, including a state the flow
// reached after the selection read. Rows already in a terminal state keep
// their fields for the stall sweep's hybrid reconciliation, which only
// clears the lock. A transition miss means the row terminalized or released
// between selection and the guarded write and is skipped.
func (c *Core) terminalizeUnrecoverableActiveRuns(ctx context.Context) error {
	var rows []TestRun

	if err := c.db.WithContext(ctx).
		Select(colTestRunID, colState).
		Where("is_active = 1 AND state NOT IN ?", terminalStateSet()).
		Find(&rows).Error; err != nil {
		return fmt.Errorf("validatorcore: list leftover active runs: %w", err)
	}

	for _, row := range rows {
		err := c.ReleaseActiveTerminalExcept(ctx, row.TestRunID, nil, ActiveTerminalUpdate{
			State:          StateInterrupted,
			TerminalReason: startupRecoveryReason,
		})
		if err == nil || errors.Is(err, ErrStateTransitionMiss) {
			continue
		}

		return err
	}

	return nil
}

// pruneTerminalRetention hard-deletes aged non-permanent terminal test_run
// rows after children-first cleanup, then prunes stats_raw for the same
// retention window. Permanent rows are spared here and tombstoned by the
// expiry sweep. PruneStats stays on stats_raw.created_at only and must not
// consult test_run or delete permanent reports.
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
