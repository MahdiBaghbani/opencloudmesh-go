// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"testing"
	"time"
)

func TestRebuildStatsAggregate_PreservesCounts(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()

	pass := GradePass

	raw1 := &StatsRaw{
		K:              "k-hash-a-1",
		HostHash:       "hash-a",
		SessionKind:    SessionKindPassiveOnly,
		Platform:       "Nextcloud",
		GradeDiscovery: new(pass),
		CreatedAt:      100,
	}

	if err := core.InsertStatsRaw(ctx, raw1); err != nil {
		t.Fatalf("insert raw: %v", err)
	}

	raw2 := &StatsRaw{
		K:              "k-hash-a-2",
		HostHash:       "hash-a",
		SessionKind:    SessionKindActiveFull,
		Platform:       "CERNBox",
		GradeDiscovery: new(GradeFail),
		CreatedAt:      200,
	}

	if err := core.InsertStatsRaw(ctx, raw2); err != nil {
		t.Fatalf("insert raw 2: %v", err)
	}

	if err := core.PruneStats(ctx, 0); err != nil {
		t.Fatalf("rebuild: %v", err)
	}

	var agg StatsAggregate
	if err := core.DB().WithContext(ctx).First(&agg, "host_hash = ?", "hash-a").Error; err != nil {
		t.Fatalf("load aggregate: %v", err)
	}

	if agg.TotalSessions != 2 {
		t.Fatalf("total_sessions = %d, want 2", agg.TotalSessions)
	}

	if agg.HealthySessions != 1 {
		t.Fatalf("healthy_sessions = %d, want 1", agg.HealthySessions)
	}

	if agg.LastPlatform != "CERNBox" {
		t.Fatalf("last_platform = %q, want CERNBox", agg.LastPlatform)
	}

	if agg.LastHealthy {
		t.Fatal("expected last_healthy false after fail grade")
	}
}

func TestRebuildStatsAggregate_LastSeenWinsByTimestamp(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()

	pass := GradePass
	fail := GradeFail

	// Insertion order must not matter: the newer snapshot wins the last-*
	// fields even when it was inserted first.
	newer := &StatsRaw{
		K:              "k-order-newer",
		HostHash:       "hash-order",
		SessionKind:    SessionKindActiveFull,
		Platform:       "CERNBox",
		GradeDiscovery: &fail,
		CreatedAt:      200,
	}

	if err := core.InsertStatsRaw(ctx, newer); err != nil {
		t.Fatalf("insert newer: %v", err)
	}

	older := &StatsRaw{
		K:              "k-order-older",
		HostHash:       "hash-order",
		SessionKind:    SessionKindPassiveOnly,
		Platform:       "Nextcloud",
		GradeDiscovery: &pass,
		CreatedAt:      100,
	}

	if err := core.InsertStatsRaw(ctx, older); err != nil {
		t.Fatalf("insert older: %v", err)
	}

	if err := core.PruneStats(ctx, 0); err != nil {
		t.Fatalf("rebuild: %v", err)
	}

	var agg StatsAggregate
	if err := core.DB().WithContext(ctx).First(&agg, "host_hash = ?", "hash-order").Error; err != nil {
		t.Fatalf("load aggregate: %v", err)
	}

	if agg.TotalSessions != 2 {
		t.Fatalf("total_sessions = %d, want 2", agg.TotalSessions)
	}

	if agg.HealthySessions != 1 {
		t.Fatalf("healthy_sessions = %d, want 1 from pass-grade older row", agg.HealthySessions)
	}

	if agg.LastPlatform != "CERNBox" {
		t.Fatalf("last_platform = %q, want CERNBox from newer snapshot", agg.LastPlatform)
	}

	if agg.LastHealthy {
		t.Fatal("expected last_healthy false from newer fail-grade snapshot")
	}

	if agg.LastSeenTS != 200 {
		t.Fatalf("last_seen_ts = %d, want 200 from newer snapshot", agg.LastSeenTS)
	}

	if agg.FirstSeenTS != 100 {
		t.Fatalf("first_seen_ts = %d, want 100 from older snapshot", agg.FirstSeenTS)
	}
}

func TestRebuildStatsAggregate_DerivesHealthyFromGrades(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()

	allNull := &StatsRaw{
		K:           "k-null",
		HostHash:    "hash-null",
		SessionKind: SessionKindPassiveOnly,
		Platform:    "Unknown",
		CreatedAt:   100,
	}

	if err := core.InsertStatsRaw(ctx, allNull); err != nil {
		t.Fatalf("insert all-null: %v", err)
	}

	pass := GradePass
	passRaw := &StatsRaw{
		K:              "k-pass",
		HostHash:       "hash-pass",
		SessionKind:    SessionKindActiveFull,
		Platform:       "Nextcloud",
		GradeDiscovery: &pass,
		CreatedAt:      200,
	}

	if err := core.InsertStatsRaw(ctx, passRaw); err != nil {
		t.Fatalf("insert pass: %v", err)
	}

	if err := core.PruneStats(ctx, 0); err != nil {
		t.Fatalf("rebuild: %v", err)
	}

	var nullAgg StatsAggregate
	if err := core.DB().WithContext(ctx).First(&nullAgg, "host_hash = ?", "hash-null").Error; err != nil {
		t.Fatalf("load all-null aggregate: %v", err)
	}

	if nullAgg.HealthySessions != 0 {
		t.Fatalf("all-null healthy_sessions = %d, want 0", nullAgg.HealthySessions)
	}

	if nullAgg.LastHealthy {
		t.Fatal("all-null grades must not set last_healthy true")
	}

	var passAgg StatsAggregate
	if err := core.DB().WithContext(ctx).First(&passAgg, "host_hash = ?", "hash-pass").Error; err != nil {
		t.Fatalf("load pass aggregate: %v", err)
	}

	if passAgg.HealthySessions != 1 {
		t.Fatalf("pass healthy_sessions = %d, want 1", passAgg.HealthySessions)
	}

	if !passAgg.LastHealthy {
		t.Fatal("pass grade must set last_healthy true")
	}
}

func TestPruneStats_RebuildsAggregateFromRaw(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()

	pass := GradePass
	now := time.Now().Unix()

	rows := []StatsRaw{
		{
			K:              "k-host-old-1",
			HostHash:       "host-old",
			SessionKind:    SessionKindPassiveOnly,
			Platform:       "Old",
			GradeDiscovery: new(pass),
			CreatedAt:      now - int64(60*24*3600),
		},
		{
			K:              "k-host-old-2",
			HostHash:       "host-old",
			SessionKind:    SessionKindPassiveOnly,
			Platform:       "Old",
			GradeDiscovery: new(pass),
			CreatedAt:      now - int64(59*24*3600),
		},
		{
			K:              "k-host-new-1",
			HostHash:       "host-new",
			SessionKind:    SessionKindActiveFull,
			Platform:       "New",
			GradeDiscovery: new(pass),
			CreatedAt:      now - 3600,
		},
	}

	for i := range rows {
		if err := core.InsertStatsRaw(ctx, &rows[i]); err != nil {
			t.Fatalf("insert raw %d: %v", i, err)
		}
	}

	if err := core.PruneStats(ctx, 30); err != nil {
		t.Fatalf("prune: %v", err)
	}

	var aggCount int64
	if err := core.DB().WithContext(ctx).Model(&StatsAggregate{}).Count(&aggCount).Error; err != nil {
		t.Fatalf("count aggregate: %v", err)
	}

	if aggCount != 1 {
		t.Fatalf("aggregate rows = %d, want 1 after prune", aggCount)
	}

	var agg StatsAggregate
	if err := core.DB().WithContext(ctx).First(&agg, "host_hash = ?", "host-new").Error; err != nil {
		t.Fatalf("load rebuilt aggregate: %v", err)
	}

	if agg.TotalSessions != 1 {
		t.Fatalf("rebuilt total_sessions = %d, want 1", agg.TotalSessions)
	}
}

func TestPruneStats_RetentionZeroRebuildsAll(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()

	pass := GradePass

	for _, host := range []string{"host-a", "host-b"} {
		if err := core.InsertStatsRaw(ctx, &StatsRaw{
			K:              "k-" + host,
			HostHash:       host,
			SessionKind:    SessionKindPassiveOnly,
			Platform:       "P",
			GradeDiscovery: new(pass),
			CreatedAt:      1,
		}); err != nil {
			t.Fatalf("insert raw: %v", err)
		}
	}

	if err := core.PruneStats(ctx, 0); err != nil {
		t.Fatalf("prune retention 0: %v", err)
	}

	var rawCount int64
	if err := core.DB().WithContext(ctx).Model(&StatsRaw{}).Count(&rawCount).Error; err != nil {
		t.Fatalf("count raw: %v", err)
	}

	if rawCount != 2 {
		t.Fatalf("raw rows = %d, want 2 when retention_days=0", rawCount)
	}

	var aggCount int64
	if err := core.DB().WithContext(ctx).Model(&StatsAggregate{}).Count(&aggCount).Error; err != nil {
		t.Fatalf("count aggregate: %v", err)
	}

	if aggCount != 2 {
		t.Fatalf("aggregate rows = %d, want 2 after retention 0 rebuild", aggCount)
	}
}

func TestPersistTerminalStats_RebuildOnlyParity(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.SetStatsHostHasher(testStatsHostHasher(t))
	ctx := t.Context()
	now := time.Now().Unix()
	pass := GradePass
	runID := "run-stats-rebuild-parity"

	seedTerminalStatsRun(t, core, runID, now)
	core.SetTerminalStatsSnapshot(runID, StatsSnapshot{GradeDiscovery: &pass})

	if err := core.persistTerminalStats(ctx, runID); err != nil {
		t.Fatalf("persist: %v", err)
	}

	var rawCount int64
	if err := core.DB().WithContext(ctx).Model(&StatsRaw{}).Count(&rawCount).Error; err != nil {
		t.Fatalf("count stats_raw: %v", err)
	}

	if rawCount != 1 {
		t.Fatalf("stats_raw count = %d, want 1", rawCount)
	}

	var raw StatsRaw
	if err := core.DB().WithContext(ctx).First(&raw).Error; err != nil {
		t.Fatalf("load stats_raw: %v", err)
	}

	var written StatsAggregate
	if err := core.DB().WithContext(ctx).First(&written, "host_hash = ?", raw.HostHash).Error; err != nil {
		t.Fatalf("load written aggregate: %v", err)
	}

	if written.TotalSessions != 1 {
		t.Fatalf("total_sessions = %d, want 1", written.TotalSessions)
	}

	var writtenRows int64
	if err := core.DB().WithContext(ctx).Model(&StatsAggregate{}).
		Where("host_hash = ?", raw.HostHash).Count(&writtenRows).Error; err != nil {
		t.Fatalf("count written aggregates: %v", err)
	}

	if writtenRows != 1 {
		t.Fatalf("stats_aggregate rows for host = %d, want exactly 1", writtenRows)
	}

	// A full rebuild from stats_raw must reproduce the terminal-write
	// aggregate exactly: the per-host rebuild is the same recomputation.
	if err := core.PruneStats(ctx, 0); err != nil {
		t.Fatalf("prune retention 0: %v", err)
	}

	var rebuilt StatsAggregate
	if err := core.DB().WithContext(ctx).First(&rebuilt, "host_hash = ?", raw.HostHash).Error; err != nil {
		t.Fatalf("load rebuilt aggregate: %v", err)
	}

	var rebuiltRows int64
	if err := core.DB().WithContext(ctx).Model(&StatsAggregate{}).
		Where("host_hash = ?", raw.HostHash).Count(&rebuiltRows).Error; err != nil {
		t.Fatalf("count rebuilt aggregates: %v", err)
	}

	if rebuiltRows != 1 {
		t.Fatalf("stats_aggregate rows for host after rebuild = %d, want exactly 1", rebuiltRows)
	}

	assertStatsAggregateContract(t, rebuilt, written)
}

func assertStatsAggregateContract(t *testing.T, got, want StatsAggregate) {
	t.Helper()

	if got.TotalSessions != want.TotalSessions {
		t.Fatalf("total_sessions = %d, want %d", got.TotalSessions, want.TotalSessions)
	}

	if got.HealthySessions != want.HealthySessions {
		t.Fatalf("healthy_sessions = %d, want %d", got.HealthySessions, want.HealthySessions)
	}

	if got.FirstSeenTS != want.FirstSeenTS {
		t.Fatalf("first_seen_ts = %d, want %d", got.FirstSeenTS, want.FirstSeenTS)
	}

	if got.LastSeenTS != want.LastSeenTS {
		t.Fatalf("last_seen_ts = %d, want %d", got.LastSeenTS, want.LastSeenTS)
	}

	if got.LastPlatform != want.LastPlatform {
		t.Fatalf("last_platform = %q, want %q", got.LastPlatform, want.LastPlatform)
	}

	if got.LastHealthy != want.LastHealthy {
		t.Fatalf("last_healthy = %v, want %v", got.LastHealthy, want.LastHealthy)
	}
}

func TestDeriveHealthy_AllNullNotHealthy(t *testing.T) {
	t.Parallel()

	if DeriveHealthy(StatsRaw{}) {
		t.Fatal("all-NULL grades must not be healthy")
	}
}

func TestDeriveHealthy_WarnNotHealthy(t *testing.T) {
	t.Parallel()

	warn := GradeWarn
	if DeriveHealthy(StatsRaw{GradeDiscovery: &warn}) {
		t.Fatal("warn grade must not be healthy")
	}
}
