// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"testing"
	"time"
)

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
	rows := statsNamedHosts("healthy", "nextcloud", 5, 0, nil)
	rows[0].GradeDiscovery = &pass

	totals := computeStatisticsTotals(rows, lastRowPerHost(rows))
	if totals.Sessions != 5 {
		t.Fatalf("sessions = %d, want 5", totals.Sessions)
	}

	if totals.UniqueHosts != 5 {
		t.Fatalf("unique_hosts = %d, want 5", totals.UniqueHosts)
	}

	if totals.HealthyPct != 20.0 {
		t.Fatalf("healthy_pct = %v, want 20.0", totals.HealthyPct)
	}

	empty := computeStatisticsTotals(nil, map[string]StatsRaw{})
	if empty.HealthyPct != 0 {
		t.Fatalf("empty healthy_pct = %v, want 0", empty.HealthyPct)
	}
}

func TestComputeStatisticsTotals_SuppressesBelowThreshold(t *testing.T) {
	t.Parallel()

	pass := GradePass
	four := statsNamedHosts("four", "nextcloud", 4, 0, &pass)
	fourTotals := computeStatisticsTotals(four, lastRowPerHost(four))

	if fourTotals != (StatisticsTotals{}) {
		t.Fatalf("four unique hosts totals = %+v, want suppressed zeros", fourTotals)
	}

	five := statsNamedHosts("five", "nextcloud", 5, 0, &pass)
	fiveTotals := computeStatisticsTotals(five, lastRowPerHost(five))

	if fiveTotals.UniqueHosts != 5 || fiveTotals.Sessions != 5 || fiveTotals.HealthyPct != 100.0 {
		t.Fatalf("five unique hosts totals = %+v, want kept", fiveTotals)
	}

	padded := append(
		statsNamedHosts("pad-named", "nextcloud", 4, 0, &pass),
		statsNamedHosts("pad-unknown", "", 3, 0, &pass)...,
	)
	paddedTotals := computeStatisticsTotals(padded, lastRowPerHost(padded))

	if paddedTotals != (StatisticsTotals{}) {
		t.Fatalf("unknown hosts must not lift totals = %+v", paddedTotals)
	}

	mixed := append(
		statsNamedHosts("kept", "nextcloud", 6, 0, &pass),
		statsNamedHosts("tiny", "small", 2, 0, &pass)...,
	)
	mixedTotals := computeStatisticsTotals(mixed, lastRowPerHost(mixed))

	if mixedTotals.UniqueHosts != 6 || mixedTotals.Sessions != 6 {
		t.Fatalf("suppressed other must not remain in totals = %+v", mixedTotals)
	}

	other := append(
		statsNamedHosts("foo", "foo", 3, 0, &pass),
		statsNamedHosts("bar", "bar", 2, 0, &pass)...,
	)
	otherTotals := computeStatisticsTotals(other, lastRowPerHost(other))

	if otherTotals.UniqueHosts != 5 || otherTotals.Sessions != 5 {
		t.Fatalf("published other totals = %+v, want 5 hosts", otherTotals)
	}
}

func TestComputeStatisticsPlatforms_KAnonAndUnknownExempt(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		rows []StatsRaw
		want map[string]int64
	}{
		{
			name: "named kept other suppressed unknown kept",
			rows: append(
				append(
					statsNamedHosts("nc", "nextcloud", 6, 0, nil),
					statsNamedHosts("sm", "small", 2, 0, nil)...,
				),
				statsHostRow("u1", "", 0, nil),
			),
			want: map[string]int64{"nextcloud": 6, "unknown": 1},
		},
		{
			name: "five named hosts kept",
			rows: statsNamedHosts("five", "nextcloud", 5, 0, nil),
			want: map[string]int64{"nextcloud": 5},
		},
		{
			name: "four named hosts suppressed",
			rows: statsNamedHosts("four", "nextcloud", 4, 0, nil),
			want: map[string]int64{},
		},
		{
			name: "other kept at five unique hosts",
			rows: append(
				statsNamedHosts("foo", "foo", 3, 0, nil),
				statsNamedHosts("bar", "bar", 2, 0, nil)...,
			),
			want: map[string]int64{"other": 5},
		},
		{
			name: "other suppressed below five",
			rows: append(
				statsNamedHosts("foo", "foo", 2, 0, nil),
				statsNamedHosts("bar", "bar", 2, 0, nil)...,
			),
			want: map[string]int64{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := platformCountMap(computeStatisticsPlatforms(lastRowPerHost(tt.rows)))
			if len(got) != len(tt.want) {
				t.Fatalf("platforms = %v, want %v", got, tt.want)
			}

			for label, count := range tt.want {
				if got[label] != count {
					t.Fatalf("platform %q count = %d, want %d (got %v)", label, got[label], count, got)
				}
			}
		})
	}
}

func TestComputeStatisticsAreas_CountsNonNullGrades(t *testing.T) {
	t.Parallel()

	pass := GradePass
	warn := GradeWarn
	fail := GradeFail
	rows := statsNamedHosts("area", "nextcloud", 6, 0, &pass)
	rows[0].GradeTLS = &warn
	rows[1].GradeDiscovery = &fail
	rows[1].GradeTLS = &pass
	rows[2].GradeDiscovery = nil
	rows[2].GradeTLS = nil
	rows[3].GradeTLS = &pass
	rows[4].GradeTLS = &fail
	rows[5].GradeTLS = &pass

	areas := statisticsAreaByName(computeStatisticsAreas(rows))
	discovery := areas["discovery"]

	if discovery.Pass != 4 || discovery.Warn != 0 || discovery.Fail != 1 {
		t.Fatalf("discovery = %+v, want pass=4 fail=1", discovery)
	}

	tls := areas["tls"]
	if tls.Pass != 3 || tls.Warn != 1 || tls.Fail != 1 {
		t.Fatalf("tls = %+v, want pass=3 warn=1 fail=1", tls)
	}
}

func TestComputeStatisticsAreas_SuppressesBelowThreshold(t *testing.T) {
	t.Parallel()

	pass := GradePass
	four := computeStatisticsAreas(statsNamedHosts("area-four", "nextcloud", 4, 0, &pass))
	discoveryFour := statisticsAreaByName(four)["discovery"]

	if discoveryFour.Pass != 0 || discoveryFour.Warn != 0 || discoveryFour.Fail != 0 {
		t.Fatalf("discovery four hosts = %+v, want suppressed zeros", discoveryFour)
	}

	five := computeStatisticsAreas(statsNamedHosts("area-five", "nextcloud", 5, 0, &pass))
	discoveryFive := statisticsAreaByName(five)["discovery"]

	if discoveryFive.Pass != 5 {
		t.Fatalf("discovery five hosts = %+v, want pass=5", discoveryFive)
	}

	mixed := statsNamedHosts("area-mixed", "nextcloud", 5, 0, &pass)
	mixed[3].GradeTLS = &pass
	mixed[4].GradeTLS = &pass
	tls := statisticsAreaByName(computeStatisticsAreas(mixed))["tls"]

	if tls.Pass != 0 || tls.Warn != 0 || tls.Fail != 0 {
		t.Fatalf("tls three hosts = %+v, want suppressed zeros", tls)
	}
}

func TestComputeStatisticsDaily_UTCBuckets(t *testing.T) {
	t.Parallel()

	pass := GradePass
	dayOne := time.Date(2026, 8, 15, 10, 0, 0, 0, time.UTC).Unix()
	dayTwo := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC).Unix()
	rows := append(
		statsNamedHosts("day-one", "nextcloud", 5, dayOne, &pass),
		statsNamedHosts("day-two", "nextcloud", 5, dayTwo, nil)...,
	)
	rows[5].GradeDiscovery = &pass
	rows[6].GradeDiscovery = &pass

	from := utcDayStartUnix(dayOne)
	to := dayTwo
	daily := computeStatisticsDaily(rows, from, to)

	if len(daily) != 2 {
		t.Fatalf("daily len = %d, want 2", len(daily))
	}

	if daily[0].TS != utcDayStartUnix(dayOne) {
		t.Fatalf("first ts = %d, want day-one start", daily[0].TS)
	}

	if daily[0].Sessions != 5 || daily[0].HealthyPct != 100.0 {
		t.Fatalf("day one = %+v, want 5 sessions and 100 pct", daily[0])
	}

	if daily[1].Sessions != 5 || daily[1].HealthyPct != 40.0 {
		t.Fatalf("day two = %+v, want 5 sessions and 40 pct", daily[1])
	}
}

func TestComputeStatisticsDaily_SuppressesBelowThreshold(t *testing.T) {
	t.Parallel()

	pass := GradePass
	dayOne := time.Date(2026, 8, 15, 10, 0, 0, 0, time.UTC).Unix()
	dayTwo := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC).Unix()
	rows := append(
		statsNamedHosts("small-day", "nextcloud", 4, dayOne, &pass),
		statsNamedHosts("kept-day", "nextcloud", 5, dayTwo, &pass)...,
	)
	rows = append(rows, statsHostRow("unknown-day", "", dayOne, &pass))

	daily := computeStatisticsDaily(rows, utcDayStartUnix(dayOne), dayTwo)
	if len(daily) != 2 {
		t.Fatalf("daily len = %d, want 2", len(daily))
	}

	if daily[0].Sessions != 0 || daily[0].HealthyPct != 0 {
		t.Fatalf("four-host day = %+v, want suppressed zeros", daily[0])
	}

	if daily[1].Sessions != 5 || daily[1].HealthyPct != 100.0 {
		t.Fatalf("five-host day = %+v, want kept", daily[1])
	}
}
