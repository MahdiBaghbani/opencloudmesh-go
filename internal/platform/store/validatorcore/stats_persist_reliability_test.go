// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/appctx"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
)

func registerStatsRawCreateFailure(t *testing.T, core *Core, injected error) func() {
	t.Helper()

	const cbName = "test_fail_stats_raw_create"

	if err := core.DB().Callback().Create().Before("gorm:create").Register(cbName, func(db *gorm.DB) {
		if db.Statement.Table != tableStatsRaw && db.Statement.Table != "stats_raw" {
			if _, ok := db.Statement.Dest.(*StatsRaw); !ok {
				if _, ok := db.Statement.Model.(*StatsRaw); !ok {
					return
				}
			}
		}

		if addErr := db.AddError(injected); !errors.Is(addErr, injected) {
			t.Errorf("inject stats_raw failure: got %v", addErr)
		}
	}); err != nil {
		t.Fatalf("register callback: %v", err)
	}

	return func() {
		if err := core.DB().Callback().Create().Remove(cbName); err != nil {
			t.Errorf("remove callback: %v", err)
		}
	}
}

func TestPersistTerminalStats_StateCASCommitsAfterStatsFailure(t *testing.T) {
	t.Parallel()

	// No stats hasher is wired, so persistence fails after the terminal
	// transition; the committed state must survive because stats persistence
	// is best-effort and decoupled from the state write.
	core := openTestCore(t)
	ctx := t.Context()

	runID := "run-stats-state-first"
	seedPassiveComplete(t, core, runID, "https://peer.example", true)

	if err := core.StopPassive(ctx, runID); err != nil {
		t.Fatalf("StopPassive: %v", err)
	}

	row, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if row.State != StateTerminalPass {
		t.Fatalf("state = %q, want %q after stats failure", row.State, StateTerminalPass)
	}

	var rawCount int64
	if err := core.DB().WithContext(ctx).Model(&StatsRaw{}).Count(&rawCount).Error; err != nil {
		t.Fatalf("count stats_raw: %v", err)
	}

	if rawCount != 0 {
		t.Fatalf("stats_raw count = %d, want 0 without a stats hasher", rawCount)
	}
}

func TestPersistTerminalStats_StateCASCommittedWhenStatsTxRollsBack(t *testing.T) {
	t.Parallel()

	// The state transition commits first; the stats transaction runs after
	// it, and a stats rollback must not touch the committed state.
	core := openTestCore(t)
	core.SetStatsHostHasher(testStatsHostHasher(t))
	ctx := t.Context()

	runID := "run-stats-state-cas-rollback"
	seedPassiveComplete(t, core, runID, "https://peer.example", true)

	unregister := registerStatsRawCreateFailure(t, core, errors.New("injected stats_raw failure"))
	defer unregister()

	if err := core.StopPassive(ctx, runID); err != nil {
		t.Fatalf("StopPassive: %v", err)
	}

	row, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if row.State != StateTerminalPass {
		t.Fatalf("state = %q, want %q committed despite stats rollback", row.State, StateTerminalPass)
	}

	if row.StatsWrittenAt != nil {
		t.Fatalf("stats_written_at = %v, want NULL from the rolled-back stats transaction", *row.StatsWrittenAt)
	}

	var rawCount int64
	if err := core.DB().WithContext(ctx).Model(&StatsRaw{}).Count(&rawCount).Error; err != nil {
		t.Fatalf("count stats_raw: %v", err)
	}

	if rawCount != 0 {
		t.Fatalf("stats_raw count = %d, want 0 from the rolled-back stats transaction", rawCount)
	}
}

func TestPersistTerminalStats_StatsWrittenAtStampedOnlyOnOptIn(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.SetStatsHostHasher(testStatsHostHasher(t))
	ctx := t.Context()
	now := time.Now().Unix()

	optInRun := "run-stats-marker-opt-in"
	optOutRun := "run-stats-marker-opt-out"

	seedTerminalStatsRun(t, core, optInRun, now)

	optOut := &TestRun{
		TestRunID:    optOutRun,
		State:        StateTerminalPass,
		TargetOrigin: "https://peer.example",
		TargetHost:   "peer.example",
		FinishedAt:   &now,
		OptInStats:   false,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := core.DB().WithContext(ctx).Create(optOut).Error; err != nil {
		t.Fatalf("seed opt-out run: %v", err)
	}

	if err := core.persistTerminalStats(ctx, optInRun); err != nil {
		t.Fatalf("persist opt-in run: %v", err)
	}

	if err := core.persistTerminalStats(ctx, optOutRun); err != nil {
		t.Fatalf("persist opt-out run: %v", err)
	}

	var inRow TestRun
	if err := core.DB().WithContext(ctx).First(&inRow, "test_run_id = ?", optInRun).Error; err != nil {
		t.Fatalf("reload opt-in run: %v", err)
	}

	if inRow.StatsWrittenAt == nil {
		t.Fatal("stats_written_at = NULL, want non-NULL after successful persist")
	}

	var outRow TestRun
	if err := core.DB().WithContext(ctx).First(&outRow, "test_run_id = ?", optOutRun).Error; err != nil {
		t.Fatalf("reload opt-out run: %v", err)
	}

	if outRow.StatsWrittenAt != nil {
		t.Fatalf("stats_written_at = %v, want NULL when opt_in_stats=0", *outRow.StatsWrittenAt)
	}

	var rawCount int64
	if err := core.DB().WithContext(ctx).Model(&StatsRaw{}).Count(&rawCount).Error; err != nil {
		t.Fatalf("count stats_raw: %v", err)
	}

	if rawCount != 1 {
		t.Fatalf("stats_raw count = %d, want 1 (opt-in run only)", rawCount)
	}
}

func TestPersistTerminalStats_RollsBackRawOnWriteFailure(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.SetStatsHostHasher(testStatsHostHasher(t))
	ctx := t.Context()
	now := time.Now().Unix()
	runID := "run-stats-rollback"

	seedTerminalStatsRun(t, core, runID, now)

	unregister := registerStatsRawCreateFailure(t, core, errors.New("injected stats_raw failure"))
	defer unregister()

	if err := core.persistTerminalStats(ctx, runID); err == nil {
		t.Fatal("expected stats_raw write failure")
	}

	var rawCount int64
	if err := core.DB().WithContext(ctx).Model(&StatsRaw{}).Count(&rawCount).Error; err != nil {
		t.Fatalf("count stats_raw: %v", err)
	}

	if rawCount != 0 {
		t.Fatalf("stats_raw count = %d, want 0 after transaction rollback", rawCount)
	}

	var row TestRun
	if err := core.DB().WithContext(ctx).First(&row, "test_run_id = ?", runID).Error; err != nil {
		t.Fatalf("reload test run: %v", err)
	}

	if row.StatsWrittenAt != nil {
		t.Fatalf("stats_written_at = %v, want NULL after transaction rollback", *row.StatsWrittenAt)
	}
}

func TestPersistTerminalStats_RetryWritesOnce(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.SetStatsHostHasher(testStatsHostHasher(t))
	ctx := t.Context()
	now := time.Now().Unix()
	runID := "run-stats-retry"

	seedTerminalStatsRun(t, core, runID, now)

	if err := core.persistTerminalStats(ctx, runID); err != nil {
		t.Fatalf("first persist: %v", err)
	}

	// A sentinel marker proves the write-once column is not restamped on retry.
	sentinel := int64(424242)
	if err := core.DB().WithContext(ctx).Exec(
		"UPDATE test_run SET stats_written_at = ? WHERE test_run_id = ?", sentinel, runID,
	).Error; err != nil {
		t.Fatalf("stamp sentinel: %v", err)
	}

	if err := core.persistTerminalStats(ctx, runID); err != nil {
		t.Fatalf("retry persist: %v", err)
	}

	var rawCount int64
	if err := core.DB().WithContext(ctx).Model(&StatsRaw{}).Count(&rawCount).Error; err != nil {
		t.Fatalf("count stats_raw: %v", err)
	}

	if rawCount != 1 {
		t.Fatalf("stats_raw count = %d, want exactly 1 after retry", rawCount)
	}

	var row TestRun
	if err := core.DB().WithContext(ctx).First(&row, "test_run_id = ?", runID).Error; err != nil {
		t.Fatalf("reload test run: %v", err)
	}

	if row.StatsWrittenAt == nil || *row.StatsWrittenAt != sentinel {
		t.Fatalf("stats_written_at = %v, want untouched sentinel %d", row.StatsWrittenAt, sentinel)
	}
}

func TestPersistTerminalStats_RetryReachesDedupConflict(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.SetStatsHostHasher(testStatsHostHasher(t))
	ctx := t.Context()
	now := time.Now().Unix()
	runID := "run-stats-retry-conflict"

	seedTerminalStatsRun(t, core, runID, now)

	if err := core.persistTerminalStats(ctx, runID); err != nil {
		t.Fatalf("first persist: %v", err)
	}

	var first StatsRaw
	if err := core.DB().WithContext(ctx).First(&first).Error; err != nil {
		t.Fatalf("load stats_raw: %v", err)
	}

	// Clearing the write-once marker lets the retry pass the guard and reach
	// the stats_raw insert, where ON CONFLICT(k) DO NOTHING absorbs the
	// duplicate. The re-stamped marker distinguishes this conflict path from
	// the guard short-circuit covered by the write-once retry test.
	if err := core.DB().WithContext(ctx).Exec(
		"UPDATE test_run SET stats_written_at = NULL WHERE test_run_id = ?", runID,
	).Error; err != nil {
		t.Fatalf("clear stats_written_at: %v", err)
	}

	if err := core.persistTerminalStats(ctx, runID); err != nil {
		t.Fatalf("conflict retry persist: %v", err)
	}

	var row TestRun
	if err := core.DB().WithContext(ctx).First(&row, "test_run_id = ?", runID).Error; err != nil {
		t.Fatalf("reload test run: %v", err)
	}

	if row.StatsWrittenAt == nil {
		t.Fatal("stats_written_at = NULL after conflict retry, want re-stamped by the passed guard")
	}

	var rawCount int64
	if err := core.DB().WithContext(ctx).Model(&StatsRaw{}).Count(&rawCount).Error; err != nil {
		t.Fatalf("count stats_raw: %v", err)
	}

	if rawCount != 1 {
		t.Fatalf("stats_raw count = %d, want exactly 1 after conflict retry", rawCount)
	}

	var surviving StatsRaw
	if err := core.DB().WithContext(ctx).First(&surviving).Error; err != nil {
		t.Fatalf("reload stats_raw: %v", err)
	}

	if surviving.ID != first.ID || surviving.K != first.K {
		t.Fatalf("surviving stats_raw = (id %d, k %q), want original (id %d, k %q)",
			surviving.ID, surviving.K, first.ID, first.K)
	}
}

func TestBestEffortPersistTerminalStats_SurvivesCanceledContext(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.SetStatsHostHasher(testStatsHostHasher(t))
	ctx := t.Context()
	now := time.Now().Unix()
	runID := "run-stats-canceled-ctx"

	row := &TestRun{
		TestRunID:    runID,
		State:        StateTerminalPass,
		TargetOrigin: "https://peer.example",
		TargetHost:   "peer.example",
		FinishedAt:   &now,
		OptInStats:   true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := core.DB().WithContext(ctx).Create(row).Error; err != nil {
		t.Fatalf("seed terminal row: %v", err)
	}

	canceledCtx, cancel := context.WithCancel(ctx)
	cancel()

	bestEffortPersistTerminalStats(core, canceledCtx, runID)

	var rawCount int64
	if err := core.DB().WithContext(ctx).Model(&StatsRaw{}).Count(&rawCount).Error; err != nil {
		t.Fatalf("count stats_raw: %v", err)
	}

	if rawCount != 1 {
		t.Fatalf("stats_raw count = %d, want 1 despite canceled caller context", rawCount)
	}
}

func TestBestEffortPersistTerminalStats_LogsPersistenceFailure(t *testing.T) {
	t.Parallel()

	capture := logutil.NewCapturingLogger(slog.LevelError)
	ctx := appctx.WithLogger(t.Context(), capture.Logger)

	core := openTestCore(t)
	now := time.Now().Unix()
	runID := "run-stats-log-fail"

	row := &TestRun{
		TestRunID:    runID,
		State:        StateTerminalPass,
		TargetOrigin: "https://peer.example",
		TargetHost:   "peer.example",
		FinishedAt:   &now,
		OptInStats:   true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := core.DB().WithContext(ctx).Create(row).Error; err != nil {
		t.Fatalf("seed terminal row: %v", err)
	}

	bestEffortPersistTerminalStats(core, ctx, runID)

	output := capture.Output()
	if !strings.Contains(output, "validator terminal stats persistence failed") {
		t.Fatalf("expected persistence failure log, got: %q", output)
	}

	if !strings.Contains(output, "test_run_id="+runID) {
		t.Fatalf("expected test_run_id in log output, got: %q", output)
	}

	if !strings.Contains(output, "error=") {
		t.Fatalf("expected structured error field in log output, got: %q", output)
	}

	if strings.Contains(output, "peer.example") {
		t.Fatalf("log output must not contain raw host, got: %q", output)
	}
}
