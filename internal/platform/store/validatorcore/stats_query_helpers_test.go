// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"fmt"
	"testing"
	"time"
)

func fixedStatsNow(t *testing.T) time.Time {
	t.Helper()

	return time.Date(2026, 8, 16, 15, 30, 0, 0, time.UTC)
}

func statsHostRow(hash, platform string, createdAt int64, discovery *string) StatsRaw {
	return StatsRaw{
		HostHash:       hash,
		Platform:       platform,
		CreatedAt:      createdAt,
		GradeDiscovery: discovery,
	}
}

func statsNamedHosts(prefix, platform string, n int, createdAt int64, discovery *string) []StatsRaw {
	rows := make([]StatsRaw, 0, n)
	for i := range n {
		rows = append(rows, statsHostRow(
			fmt.Sprintf("%s-%d", prefix, i),
			platform,
			createdAt,
			discovery,
		))
	}

	return rows
}

func platformCountMap(platforms []StatisticsPlatform) map[string]int64 {
	counts := map[string]int64{}
	for _, item := range platforms {
		counts[item.Platform] = item.Count
	}

	return counts
}

func statisticsAreaByName(areas []StatisticsArea) map[string]StatisticsArea {
	byName := map[string]StatisticsArea{}
	for _, area := range areas {
		byName[area.Area] = area
	}

	return byName
}

func insertStatsRows(t *testing.T, core *Core, rows []StatsRaw) {
	t.Helper()

	for i := range rows {
		if rows[i].K == "" {
			rows[i].K = fmt.Sprintf("k-%s-%d", rows[i].HostHash, i)
		}

		if err := core.InsertStatsRaw(t.Context(), &rows[i]); err != nil {
			t.Fatalf("InsertStatsRaw: %v", err)
		}
	}
}

func mixedHistoryDays(t *testing.T) (dayOne, dayTwo int64) {
	t.Helper()

	dayOne = time.Date(2026, 8, 15, 10, 0, 0, 0, time.UTC).Unix()
	dayTwo = time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC).Unix()

	return dayOne, dayTwo
}

func requireDailyLen(t *testing.T, daily []StatisticsDaily, want int) {
	t.Helper()

	if len(daily) != want {
		t.Fatalf("daily len = %d, want %d", len(daily), want)
	}
}
