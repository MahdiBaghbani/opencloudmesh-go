// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"testing"
	"time"
)

func fixedStatsNow(t *testing.T) time.Time {
	t.Helper()

	return time.Date(2026, 8, 16, 15, 30, 0, 0, time.UTC)
}

func TestBuildStatisticsWindow_DefaultAndAllTime(t *testing.T) {
	t.Parallel()

	now := fixedStatsNow(t)
	window := BuildStatisticsWindow(14, now)

	if window.Days != 14 {
		t.Fatalf("days = %d, want 14", window.Days)
	}

	if window.Selector != "days=14" {
		t.Fatalf("selector = %q, want days=14", window.Selector)
	}

	wantFrom := time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC).Unix()
	if window.From != wantFrom {
		t.Fatalf("from = %d, want %d", window.From, wantFrom)
	}

	if window.To != now.Unix() {
		t.Fatalf("to = %d, want %d", window.To, now.Unix())
	}

	allTime := BuildStatisticsWindow(0, now)
	if !allTime.AllTime {
		t.Fatal("expected all-time window")
	}

	if allTime.Selector != "days=0" {
		t.Fatalf("selector = %q, want days=0", allTime.Selector)
	}

	if allTime.From != 0 {
		t.Fatalf("from = %d, want 0 before query", allTime.From)
	}
}

func TestLastRowPerHost_CreatedAtAndIDTieBreak(t *testing.T) {
	t.Parallel()

	pass := GradePass
	warn := GradeWarn

	rows := []StatsRaw{
		{ID: 1, HostHash: "host-a", CreatedAt: 100, GradeDiscovery: &pass},
		{ID: 2, HostHash: "host-a", CreatedAt: 200, GradeDiscovery: &warn},
		{ID: 3, HostHash: "host-a", CreatedAt: 200, GradeDiscovery: &pass},
		{ID: 4, HostHash: "host-b", CreatedAt: 150},
	}

	last := lastRowPerHost(rows)

	if got := last["host-a"].ID; got != 3 {
		t.Fatalf("host-a last id = %d, want 3", got)
	}

	if !DeriveHealthy(last["host-a"]) {
		t.Fatal("expected host-a latest row to be healthy")
	}

	if DeriveHealthy(last["host-b"]) {
		t.Fatal("expected all-null host-b to be unhealthy")
	}
}

func TestComputeStatisticsTotals_HealthyPctZeroSafe(t *testing.T) {
	t.Parallel()

	pass := GradePass
	rows := []StatsRaw{
		{ID: 1, HostHash: "h1", GradeDiscovery: &pass},
		{ID: 2, HostHash: "h2"},
	}

	totals := computeStatisticsTotals(rows, lastRowPerHost(rows))
	if totals.Sessions != 2 {
		t.Fatalf("sessions = %d, want 2", totals.Sessions)
	}

	if totals.UniqueHosts != 2 {
		t.Fatalf("unique_hosts = %d, want 2", totals.UniqueHosts)
	}

	if totals.HealthyPct != 50.0 {
		t.Fatalf("healthy_pct = %v, want 50.0", totals.HealthyPct)
	}

	empty := computeStatisticsTotals(nil, map[string]StatsRaw{})
	if empty.HealthyPct != 0 {
		t.Fatalf("empty healthy_pct = %v, want 0", empty.HealthyPct)
	}
}

func TestComputeStatisticsPlatforms_KAnonAndUnknownExempt(t *testing.T) {
	t.Parallel()

	lastByHost := map[string]StatsRaw{
		"h1": {Platform: "nextcloud"},
		"h2": {Platform: "nextcloud"},
		"h3": {Platform: "nextcloud"},
		"h4": {Platform: "nextcloud"},
		"h5": {Platform: "nextcloud"},
		"h6": {Platform: "nextcloud"},
		"h7": {Platform: "small"},
		"h8": {Platform: "small"},
		"h9": {Platform: ""},
	}

	platforms := computeStatisticsPlatforms(lastByHost)
	counts := map[string]int64{}

	for _, item := range platforms {
		counts[item.Platform] = item.Count
	}

	if counts["nextcloud"] != 6 {
		t.Fatalf("nextcloud count = %d, want 6", counts["nextcloud"])
	}

	if counts["other"] != 2 {
		t.Fatalf("other count = %d, want 2 for k<=5 platforms", counts["other"])
	}

	if counts["unknown"] != 1 {
		t.Fatalf("unknown count = %d, want 1", counts["unknown"])
	}

	if _, ok := counts["small"]; ok {
		t.Fatal("small platform must be folded into other")
	}
}

func TestComputeStatisticsAreas_CountsNonNullGrades(t *testing.T) {
	t.Parallel()

	pass := GradePass
	warn := GradeWarn
	fail := GradeFail

	rows := []StatsRaw{
		{GradeDiscovery: &pass, GradeTLS: &warn},
		{GradeDiscovery: &fail},
		{GradeDiscovery: nil, GradeTLS: nil},
	}

	areas := computeStatisticsAreas(rows)
	byName := map[string]StatisticsArea{}

	for _, area := range areas {
		byName[area.Area] = area
	}

	discovery := byName["discovery"]
	if discovery.Pass != 1 || discovery.Warn != 0 || discovery.Fail != 1 {
		t.Fatalf("discovery = %+v, want pass=1 fail=1", discovery)
	}

	tls := byName["tls"]
	if tls.Pass != 0 || tls.Warn != 1 || tls.Fail != 0 {
		t.Fatalf("tls = %+v, want warn=1", tls)
	}
}

func TestComputeStatisticsDaily_UTCBuckets(t *testing.T) {
	t.Parallel()

	pass := GradePass
	dayOne := time.Date(2026, 8, 15, 10, 0, 0, 0, time.UTC).Unix()
	dayTwo := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC).Unix()

	rows := []StatsRaw{
		{ID: 1, HostHash: "h1", CreatedAt: dayOne, GradeDiscovery: &pass},
		{ID: 2, HostHash: "h1", CreatedAt: dayTwo},
		{ID: 3, HostHash: "h2", CreatedAt: dayTwo, GradeDiscovery: &pass},
	}

	from := utcDayStartUnix(dayOne)
	to := dayTwo
	daily := computeStatisticsDaily(rows, from, to)

	if len(daily) != 2 {
		t.Fatalf("daily len = %d, want 2", len(daily))
	}

	if daily[0].TS != utcDayStartUnix(dayOne) {
		t.Fatalf("first ts = %d, want day-one start", daily[0].TS)
	}

	if daily[0].Sessions != 1 || daily[0].HealthyPct != 100.0 {
		t.Fatalf("day one = %+v, want 1 session and 100 pct", daily[0])
	}

	if daily[1].Sessions != 2 || daily[1].HealthyPct != 50.0 {
		t.Fatalf("day two = %+v, want 2 sessions and 50 pct", daily[1])
	}
}

func TestQueryFederationTesterStatistics_AllTimeOmitsDaily(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	pass := GradePass

	rows := []StatsRaw{
		{K: "k-all-time-h1", HostHash: "h1", CreatedAt: 100, GradeDiscovery: &pass, Platform: "nextcloud"},
		{K: "k-all-time-h2", HostHash: "h2", CreatedAt: 200, Platform: "cernbox"},
	}

	for i := range rows {
		if err := core.InsertStatsRaw(ctx, &rows[i]); err != nil {
			t.Fatalf("InsertStatsRaw: %v", err)
		}
	}

	window := BuildStatisticsWindow(0, fixedStatsNow(t))

	stats, err := core.QueryFederationTesterStatistics(ctx, window)
	if err != nil {
		t.Fatalf("QueryFederationTesterStatistics: %v", err)
	}

	if !stats.DailyOmitted {
		t.Fatal("expected daily_omitted for all-time")
	}

	if len(stats.Daily) != 0 {
		t.Fatalf("daily len = %d, want 0", len(stats.Daily))
	}

	if stats.Window.From != 100 {
		t.Fatalf("from = %d, want earliest created_at 100", stats.Window.From)
	}

	if stats.Totals.Sessions != 2 {
		t.Fatalf("sessions = %d, want 2", stats.Totals.Sessions)
	}
}

func TestQueryFederationTesterStatistics_WindowFiltersRows(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	pass := GradePass

	now := fixedStatsNow(t)
	inWindow := now.Add(-2 * 24 * time.Hour).Unix()
	outWindow := now.Add(-20 * 24 * time.Hour).Unix()

	rows := []StatsRaw{
		{K: "k-window-in", HostHash: "in", CreatedAt: inWindow, GradeDiscovery: &pass, Platform: "nextcloud"},
		{K: "k-window-out", HostHash: "out", CreatedAt: outWindow, GradeDiscovery: &pass, Platform: "nextcloud"},
	}

	for i := range rows {
		if err := core.InsertStatsRaw(ctx, &rows[i]); err != nil {
			t.Fatalf("InsertStatsRaw: %v", err)
		}
	}

	window := BuildStatisticsWindow(14, now)

	stats, err := core.QueryFederationTesterStatistics(ctx, window)
	if err != nil {
		t.Fatalf("QueryFederationTesterStatistics: %v", err)
	}

	if stats.Totals.Sessions != 1 {
		t.Fatalf("sessions = %d, want 1", stats.Totals.Sessions)
	}

	if stats.Totals.UniqueHosts != 1 {
		t.Fatalf("unique_hosts = %d, want 1", stats.Totals.UniqueHosts)
	}
}
