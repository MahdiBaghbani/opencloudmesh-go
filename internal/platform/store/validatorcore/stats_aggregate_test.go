// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"testing"
	"time"
)

func TestStatsAggregate_TableAbsent(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)

	if core.DB().Migrator().HasTable(tableStatsAggregate) {
		t.Fatal("stats_aggregate must not exist")
	}
}

func TestPruneStats_DeletesOldRawOnly(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	now := time.Now().Unix()
	pass := GradePass

	if err := core.InsertStatsRaw(ctx, &StatsRaw{
		K:              "k-old",
		HostHash:       "hash-a",
		SessionKind:    SessionKindPassiveOnly,
		Platform:       "old",
		GradeDiscovery: &pass,
		CreatedAt:      now - int64(60*24*3600),
	}); err != nil {
		t.Fatalf("insert old raw: %v", err)
	}

	if err := core.InsertStatsRaw(ctx, &StatsRaw{
		K:              "k-new",
		HostHash:       "hash-a",
		SessionKind:    SessionKindActiveFull,
		Platform:       "new",
		GradeDiscovery: &pass,
		CreatedAt:      now - 3600,
	}); err != nil {
		t.Fatalf("insert new raw: %v", err)
	}

	if err := core.PruneStats(ctx, 0); err != nil {
		t.Fatalf("PruneStats(0): %v", err)
	}

	var kept int64
	if err := core.DB().WithContext(ctx).Model(&StatsRaw{}).Count(&kept).Error; err != nil {
		t.Fatalf("count after no-op prune: %v", err)
	}

	if kept != 2 {
		t.Fatalf("PruneStats(0) must leave raw rows untouched, got %d", kept)
	}

	if err := core.PruneStats(ctx, 30); err != nil {
		t.Fatalf("PruneStats(30): %v", err)
	}

	var remaining []StatsRaw
	if err := core.DB().WithContext(ctx).Find(&remaining).Error; err != nil {
		t.Fatalf("load remaining raw: %v", err)
	}

	if len(remaining) != 1 || remaining[0].K != "k-new" {
		t.Fatalf("remaining raw = %+v, want only k-new", remaining)
	}
}

func TestQueryFederationTesterStatistics_AllTimeFromMinCreatedAt(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	pass := GradePass

	if err := core.InsertStatsRaw(ctx, &StatsRaw{
		K:              "k-early",
		HostHash:       "hash-a",
		SessionKind:    SessionKindPassiveOnly,
		Platform:       "nextcloud",
		GradeDiscovery: &pass,
		CreatedAt:      1_700_000_000,
	}); err != nil {
		t.Fatalf("insert early raw: %v", err)
	}

	if err := core.InsertStatsRaw(ctx, &StatsRaw{
		K:              "k-late",
		HostHash:       "hash-b",
		SessionKind:    SessionKindActiveFull,
		Platform:       "nextcloud",
		GradeDiscovery: &pass,
		CreatedAt:      1_700_086_400,
	}); err != nil {
		t.Fatalf("insert late raw: %v", err)
	}

	got, err := core.QueryFederationTesterStatistics(ctx, BuildStatisticsWindow(0, time.Unix(1_700_086_400, 0).UTC()))
	if err != nil {
		t.Fatalf("query all-time: %v", err)
	}

	if got.Window.From != 1_700_000_000 {
		t.Fatalf("all-time From = %d, want MIN(stats_raw.created_at)=1700000000", got.Window.From)
	}
}
