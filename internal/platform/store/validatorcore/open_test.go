// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/sqlitecore"
)

func TestAttach_MigratesValidatorTablesOnSharedHandle(t *testing.T) {
	t.Parallel()

	sqlCore, err := sqlitecore.Open(t.TempDir())
	if err != nil {
		t.Fatalf("sqlitecore.Open: %v", err)
	}

	t.Cleanup(func() {
		if closeErr := sqlCore.Close(); closeErr != nil {
			t.Errorf("sqlitecore.Close: %v", closeErr)
		}
	})

	core, err := Attach(sqlCore.DB(), DefaultSessionConfig())
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}

	for _, name := range []string{"test_run", "share_correlation", "stats_raw", "stats_aggregate"} {
		if !core.DB().Migrator().HasTable(name) {
			t.Fatalf("Attach must create validator table %q", name)
		}
	}
}

func TestPruneTerminalRetention_RebuildsStatsAggregate(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.SetSessionConfig(SessionConfig{TerminalRetentionDays: 30})

	ctx := t.Context()
	now := time.Now().Unix()
	pass := GradePass
	hostHash := "host-retention"

	staleRaw := StatsRaw{
		HostHash:       hostHash,
		SessionKind:    SessionKindPassiveOnly,
		Platform:       "Stale",
		GradeDiscovery: new(pass),
		CreatedAt:      now - int64(60*24*3600),
	}

	recentRaw := StatsRaw{
		HostHash:       hostHash,
		SessionKind:    SessionKindActiveFull,
		Platform:       "Recent",
		GradeDiscovery: new(pass),
		CreatedAt:      now - 3600,
	}

	for _, row := range []StatsRaw{staleRaw, recentRaw} {
		if err := core.InsertStatsRaw(ctx, &row); err != nil {
			t.Fatalf("insert stats_raw: %v", err)
		}
	}

	if err := core.DB().WithContext(ctx).Create(&StatsAggregate{
		HostHash:        hostHash,
		TotalSessions:   99,
		HealthySessions: 99,
		LastPlatform:    "Stale",
		LastHealthy:     true,
		FirstSeenTS:     1,
		LastSeenTS:      1,
	}).Error; err != nil {
		t.Fatalf("seed stale aggregate: %v", err)
	}

	staleFinished := now - int64(60*24*3600)
	recentFinished := now - 3600

	for _, row := range []TestRun{
		{
			TestRunID:   "run-stale-terminal",
			State:       StateTerminalFail,
			SessionKind: SessionKindPassiveOnly,
			TargetHost:  "stale.example",
			FinishedAt:  &staleFinished,
			CreatedAt:   staleFinished,
			UpdatedAt:   staleFinished,
		},
		{
			TestRunID:   "run-recent-terminal",
			State:       StateTerminalPass,
			SessionKind: SessionKindActiveFull,
			TargetHost:  "recent.example",
			FinishedAt:  &recentFinished,
			CreatedAt:   recentFinished,
			UpdatedAt:   recentFinished,
		},
	} {
		if err := core.DB().WithContext(ctx).Create(&row).Error; err != nil {
			t.Fatalf("seed terminal session: %v", err)
		}
	}

	if err := core.pruneTerminalRetention(ctx, 30); err != nil {
		t.Fatalf("pruneTerminalRetention: %v", err)
	}

	var rawCount int64
	if err := core.DB().WithContext(ctx).Model(&StatsRaw{}).Count(&rawCount).Error; err != nil {
		t.Fatalf("count stats_raw: %v", err)
	}

	if rawCount != 1 {
		t.Fatalf("stats_raw rows = %d, want 1 after retention prune", rawCount)
	}

	var agg StatsAggregate
	if err := core.DB().WithContext(ctx).First(&agg, "host_hash = ?", hostHash).Error; err != nil {
		t.Fatalf("load rebuilt aggregate: %v", err)
	}

	if agg.TotalSessions != 1 {
		t.Fatalf("rebuilt total_sessions = %d, want 1", agg.TotalSessions)
	}

	if agg.LastPlatform != "Recent" {
		t.Fatalf("rebuilt last_platform = %q, want Recent", agg.LastPlatform)
	}

	var terminalCount int64
	if err := core.DB().WithContext(ctx).Model(&TestRun{}).
		Where("state IN ?", []string{StateTerminalPass, StateTerminalFail}).
		Count(&terminalCount).Error; err != nil {
		t.Fatalf("count terminal sessions: %v", err)
	}

	if terminalCount != 1 {
		t.Fatalf("terminal test_run rows = %d, want 1 after retention prune", terminalCount)
	}
}

func TestStartupMaintenance_PrunesTerminalRetention(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.SetSessionConfig(SessionConfig{
		InFlightPassiveLimit:  10,
		CreatedTTLSeconds:     3600,
		TerminalRetentionDays: 30,
	})

	ctx := t.Context()
	now := time.Now().Unix()
	pass := GradePass

	if err := core.InsertStatsRaw(ctx, &StatsRaw{
		HostHash:       "startup-host",
		SessionKind:    SessionKindPassiveOnly,
		Platform:       "Old",
		GradeDiscovery: new(pass),
		CreatedAt:      now - int64(60*24*3600),
	}); err != nil {
		t.Fatalf("insert stale stats_raw: %v", err)
	}

	if err := core.InsertStatsRaw(ctx, &StatsRaw{
		HostHash:       "startup-host",
		SessionKind:    SessionKindPassiveOnly,
		Platform:       "New",
		GradeDiscovery: new(pass),
		CreatedAt:      now - 3600,
	}); err != nil {
		t.Fatalf("insert recent stats_raw: %v", err)
	}

	if err := core.startupMaintenance(ctx); err != nil {
		t.Fatalf("startupMaintenance: %v", err)
	}

	var agg StatsAggregate
	if err := core.DB().WithContext(ctx).First(&agg, "host_hash = ?", "startup-host").Error; err != nil {
		t.Fatalf("load aggregate after startup maintenance: %v", err)
	}

	if agg.TotalSessions != 1 {
		t.Fatalf("aggregate total_sessions = %d, want 1 after startup prune/rebuild", agg.TotalSessions)
	}

	if agg.LastPlatform != "New" {
		t.Fatalf("aggregate last_platform = %q, want New", agg.LastPlatform)
	}
}
