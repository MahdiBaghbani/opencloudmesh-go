// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"testing"
	"time"
)

func TestComputeStatistics_LatestSuppressedHostExcludedFromHistory(t *testing.T) {
	t.Parallel()

	pass := GradePass
	dayOne, dayTwo := mixedHistoryDays(t)
	rows := statsNamedHosts("kept", "nextcloud", 5, dayOne, &pass)

	for i := range 4 {
		rows[i].GradeTLS = &pass
	}

	old := statsHostRow("mixed", "nextcloud", dayOne, &pass)
	old.GradeTLS = &pass
	latest := statsHostRow("mixed", "small", dayTwo, &pass)
	latest.GradeTLS = &pass
	rows = append(rows, old, latest)

	totals := computeStatisticsTotals(rows, lastRowPerHost(rows))
	if totals.UniqueHosts != 5 || totals.Sessions != 5 {
		t.Fatalf("totals = %+v, want 5 hosts and 5 sessions", totals)
	}

	areas := statisticsAreaByName(computeStatisticsAreas(rows))
	if areas["discovery"].Pass != 5 {
		t.Fatalf("discovery = %+v, want pass=5", areas["discovery"])
	}

	tls := areas["tls"]
	if tls.Pass != 0 || tls.Warn != 0 || tls.Fail != 0 {
		t.Fatalf("tls = %+v, want suppressed zeros", tls)
	}

	daily := computeStatisticsDaily(rows, utcDayStartUnix(dayOne), dayTwo)
	requireDailyLen(t, daily, 2)

	if daily[0].Sessions != 5 {
		t.Fatalf("day one = %+v, want 5 sessions", daily[0])
	}

	if daily[1].Sessions != 0 || daily[1].HealthyPct != 0 {
		t.Fatalf("day two = %+v, want suppressed zeros", daily[1])
	}
}

func TestComputeStatistics_LatestPublishedHostContributesOlderRows(t *testing.T) {
	t.Parallel()

	pass := GradePass
	dayOne, dayTwo := mixedHistoryDays(t)
	rows := append(
		statsNamedHosts("kept", "nextcloud", 5, dayOne, &pass),
		statsHostRow("mixed", "small", dayOne, &pass),
		statsHostRow("mixed", "nextcloud", dayTwo, &pass),
	)

	totals := computeStatisticsTotals(rows, lastRowPerHost(rows))
	if totals.UniqueHosts != 6 || totals.Sessions != 7 {
		t.Fatalf("totals = %+v, want 6 hosts and 7 sessions", totals)
	}

	discovery := statisticsAreaByName(computeStatisticsAreas(rows))["discovery"]
	if discovery.Pass != 7 {
		t.Fatalf("discovery = %+v, want pass=7", discovery)
	}

	daily := computeStatisticsDaily(rows, utcDayStartUnix(dayOne), dayTwo)
	requireDailyLen(t, daily, 2)

	if daily[0].Sessions != 6 {
		t.Fatalf("day one = %+v, want 6 sessions including older row", daily[0])
	}

	if daily[1].Sessions != 0 || daily[1].HealthyPct != 0 {
		t.Fatalf("day two = %+v, want suppressed zeros", daily[1])
	}
}

func TestComputeStatistics_UnknownLatestHostExemptAndExcludedFromAggregates(t *testing.T) {
	t.Parallel()

	pass := GradePass
	dayOne, dayTwo := mixedHistoryDays(t)
	rows := append(
		statsNamedHosts("kept", "nextcloud", 5, dayOne, &pass),
		statsHostRow("mixed", "nextcloud", dayOne, &pass),
		statsHostRow("mixed", "", dayTwo, &pass),
	)

	got := platformCountMap(computeStatisticsPlatforms(lastRowPerHost(rows)))
	if got["nextcloud"] != 5 || got["unknown"] != 1 || len(got) != 2 {
		t.Fatalf("platforms = %v, want nextcloud=5 unknown=1", got)
	}

	totals := computeStatisticsTotals(rows, lastRowPerHost(rows))
	if totals.UniqueHosts != 5 || totals.Sessions != 5 {
		t.Fatalf("totals = %+v, want 5 hosts and 5 sessions", totals)
	}

	discovery := statisticsAreaByName(computeStatisticsAreas(rows))["discovery"]
	if discovery.Pass != 5 {
		t.Fatalf("discovery = %+v, want pass=5", discovery)
	}

	daily := computeStatisticsDaily(rows, utcDayStartUnix(dayOne), dayTwo)
	if daily[0].Sessions != 5 {
		t.Fatalf("day one = %+v, want 5 sessions", daily[0])
	}

	if daily[1].Sessions != 0 {
		t.Fatalf("day two = %+v, want suppressed zeros", daily[1])
	}
}

func TestQueryFederationTesterStatistics_MixedHistoryDoesNotLeakSuppressedHost(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	pass := GradePass
	now := fixedStatsNow(t)
	dayOne := time.Date(2026, 8, 15, 10, 0, 0, 0, time.UTC).Unix()
	dayTwo := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC).Unix()
	rows := append(
		statsNamedHosts("kept", "nextcloud", 5, dayOne, &pass),
		statsHostRow("mixed", "nextcloud", dayOne, &pass),
		statsHostRow("mixed", "small", dayTwo, &pass),
	)
	insertStatsRows(t, core, rows)

	stats, err := core.QueryFederationTesterStatistics(t.Context(), BuildStatisticsWindow(14, now))
	if err != nil {
		t.Fatalf("QueryFederationTesterStatistics: %v", err)
	}

	if stats.Totals.UniqueHosts != 5 || stats.Totals.Sessions != 5 {
		t.Fatalf("totals = %+v, want 5 hosts and 5 sessions", stats.Totals)
	}

	discovery := statisticsAreaByName(stats.Areas)["discovery"]
	if discovery.Pass != 5 {
		t.Fatalf("discovery = %+v, want pass=5", discovery)
	}

	dayOneStart := utcDayStartUnix(dayOne)
	dayTwoStart := utcDayStartUnix(dayTwo)

	var dayOneBucket, dayTwoBucket StatisticsDaily

	for _, bucket := range stats.Daily {
		switch bucket.TS {
		case dayOneStart:
			dayOneBucket = bucket
		case dayTwoStart:
			dayTwoBucket = bucket
		}
	}

	if dayOneBucket.Sessions != 5 {
		t.Fatalf("day one = %+v, want 5 sessions", dayOneBucket)
	}

	if dayTwoBucket.Sessions != 0 {
		t.Fatalf("day two = %+v, want suppressed zeros", dayTwoBucket)
	}

	var kept int64
	if err := core.DB().WithContext(t.Context()).Model(&StatsRaw{}).Count(&kept).Error; err != nil {
		t.Fatalf("count stats_raw: %v", err)
	}

	if kept != 7 {
		t.Fatalf("stats_raw count = %d, want 7", kept)
	}
}

func TestQueryFederationTesterStatistics_AllTimeOmitsDaily(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	pass := GradePass
	insertStatsRows(t, core, statsNamedHosts("all-time", "nextcloud", 5, 100, &pass))

	stats, err := core.QueryFederationTesterStatistics(
		t.Context(),
		BuildStatisticsWindow(0, fixedStatsNow(t)),
	)
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

	if stats.Totals.Sessions != 5 {
		t.Fatalf("sessions = %d, want 5", stats.Totals.Sessions)
	}
}

func TestQueryFederationTesterStatistics_WindowFiltersRows(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	pass := GradePass
	now := fixedStatsNow(t)
	inWindow := now.Add(-2 * 24 * time.Hour).Unix()
	outWindow := now.Add(-20 * 24 * time.Hour).Unix()
	rows := statsNamedHosts("window-in", "nextcloud", 5, inWindow, &pass)
	rows = append(rows, statsHostRow("window-out", "nextcloud", outWindow, &pass))
	insertStatsRows(t, core, rows)

	stats, err := core.QueryFederationTesterStatistics(t.Context(), BuildStatisticsWindow(14, now))
	if err != nil {
		t.Fatalf("QueryFederationTesterStatistics: %v", err)
	}

	if stats.Totals.Sessions != 5 {
		t.Fatalf("sessions = %d, want 5", stats.Totals.Sessions)
	}

	if stats.Totals.UniqueHosts != 5 {
		t.Fatalf("unique_hosts = %d, want 5", stats.Totals.UniqueHosts)
	}
}

func TestQueryFederationTesterStatistics_LeavesRawRows(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	pass := GradePass
	insertStatsRows(t, core, statsNamedHosts("raw-keep", "nextcloud", 4, 200, &pass))

	stats, err := core.QueryFederationTesterStatistics(
		t.Context(),
		BuildStatisticsWindow(0, fixedStatsNow(t)),
	)
	if err != nil {
		t.Fatalf("QueryFederationTesterStatistics: %v", err)
	}

	if stats.Totals != (StatisticsTotals{}) {
		t.Fatalf("totals = %+v, want suppressed zeros", stats.Totals)
	}

	var kept int64
	if err := core.DB().WithContext(t.Context()).Model(&StatsRaw{}).Count(&kept).Error; err != nil {
		t.Fatalf("count stats_raw: %v", err)
	}

	if kept != 4 {
		t.Fatalf("stats_raw count = %d, want 4", kept)
	}
}
