// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/appctx"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
)

func TestInsertStatsRawAndAggregate_RollsBackRawOnAggregateFailure(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	pass := GradePass
	now := time.Now().Unix()

	raw := &StatsRaw{
		K:              "k-rollback",
		HostHash:       "hash-rollback",
		SessionKind:    SessionKindPassiveOnly,
		GradeDiscovery: &pass,
		CreatedAt:      now,
	}

	if err := core.DB().WithContext(ctx).Exec("DROP TABLE stats_aggregate").Error; err != nil {
		t.Fatalf("drop stats_aggregate: %v", err)
	}

	if err := core.insertStatsRawAndAggregate(ctx, raw); err == nil {
		t.Fatal("expected aggregate failure")
	}

	var rawCount int64
	if err := core.DB().WithContext(ctx).Model(&StatsRaw{}).Count(&rawCount).Error; err != nil {
		t.Fatalf("count stats_raw: %v", err)
	}

	if rawCount != 0 {
		t.Fatalf("stats_raw count = %d, want 0 after transaction rollback", rawCount)
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
		SessionKind:  SessionKindPassiveOnly,
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
		SessionKind:  SessionKindPassiveOnly,
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
