// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

const (
	// statsPlatformKAnonymity is the k-anonymity threshold for platform buckets.
	// Platforms with at most this many unique hosts are folded into "other".
	// The "unknown" platform label is exempt from suppression.
	statsPlatformKAnonymity = 5

	statsPlatformOther   = "other"
	statsPlatformUnknown = "unknown"
)

// StatisticsQueryWindow describes the inclusive statistics read window.
type StatisticsQueryWindow struct {
	Days     int
	From     int64
	To       int64
	Selector string
	AllTime  bool
}

// StatisticsTotals holds aggregate session and host health totals.
type StatisticsTotals struct {
	Sessions    int64
	UniqueHosts int64
	HealthyPct  float64
}

// StatisticsPlatform holds one k-anonymized platform distribution bucket.
type StatisticsPlatform struct {
	Platform string
	Count    int64
	Pct      float64
}

// StatisticsArea holds pass/warn/fail counts for one conformance area.
type StatisticsArea struct {
	Area string
	Pass int64
	Warn int64
	Fail int64
}

// StatisticsDaily holds one UTC-day aggregate bucket.
type StatisticsDaily struct {
	TS         int64
	Sessions   int64
	HealthyPct float64
}

// FederationTesterStatistics is the public anonymous statistics payload.
type FederationTesterStatistics struct {
	Schema       string
	Window       StatisticsQueryWindow
	Totals       StatisticsTotals
	Platforms    []StatisticsPlatform
	Areas        []StatisticsArea
	Daily        []StatisticsDaily
	DailyOmitted bool
}

// BuildStatisticsWindow computes the locked from/to window for a days selector.
func BuildStatisticsWindow(days int, now time.Time) StatisticsQueryWindow {
	now = now.UTC()

	if days == 0 {
		return StatisticsQueryWindow{
			Days:     0,
			To:       now.Unix(),
			Selector: "days=0",
			AllTime:  true,
		}
	}

	todayStart := utcDayStartUnix(now.Unix())
	from := todayStart - int64(days-1)*secondsPerDay

	return StatisticsQueryWindow{
		Days:     days,
		From:     from,
		To:       now.Unix(),
		Selector: fmt.Sprintf("days=%d", days),
		AllTime:  false,
	}
}

const secondsPerDay = 24 * 60 * 60

// QueryFederationTesterStatistics loads aggregate-only public statistics for
// the selected window. Raw host identifiers never appear in the result.
func (c *Core) QueryFederationTesterStatistics(
	ctx context.Context,
	window StatisticsQueryWindow,
) (*FederationTesterStatistics, error) {
	if c == nil || c.db == nil {
		return nil, errors.New("validatorcore: store is not configured")
	}

	rows, err := c.loadStatsRawForWindow(ctx, window)
	if err != nil {
		return nil, err
	}

	if window.AllTime {
		window.From = earliestCreatedAt(rows)
		if window.From == 0 {
			var minFirst int64

			if aggErr := c.db.WithContext(ctx).
				Model(&StatsAggregate{}).
				Select("COALESCE(MIN(first_seen_ts), 0)").
				Scan(&minFirst).Error; aggErr != nil {
				return nil, fmt.Errorf("validatorcore: min first_seen_ts: %w", aggErr)
			}

			window.From = minFirst
		}
	}

	lastByHost := lastRowPerHost(rows)

	result := &FederationTesterStatistics{
		Schema: "federation_tester_statistics.v1",
		Window: window,
		Totals: computeStatisticsTotals(rows, lastByHost),
		Areas:  computeStatisticsAreas(rows),
	}

	result.Platforms = computeStatisticsPlatforms(lastByHost)

	if window.AllTime {
		result.DailyOmitted = true
		result.Daily = []StatisticsDaily{}
	} else {
		result.Daily = computeStatisticsDaily(rows, window.From, window.To)
	}

	return result, nil
}

func (c *Core) loadStatsRawForWindow(ctx context.Context, window StatisticsQueryWindow) ([]StatsRaw, error) {
	query := c.db.WithContext(ctx).Model(&StatsRaw{})

	if !window.AllTime {
		query = query.Where("created_at >= ? AND created_at <= ?", window.From, window.To)
	}

	var rows []StatsRaw
	if err := query.Order("host_hash ASC, created_at ASC, id ASC").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("validatorcore: load stats_raw: %w", err)
	}

	return rows, nil
}

func earliestCreatedAt(rows []StatsRaw) int64 {
	if len(rows) == 0 {
		return 0
	}

	minTS := rows[0].CreatedAt
	for _, row := range rows[1:] {
		if row.CreatedAt < minTS {
			minTS = row.CreatedAt
		}
	}

	return minTS
}

func lastRowPerHost(rows []StatsRaw) map[string]StatsRaw {
	if len(rows) == 0 {
		return map[string]StatsRaw{}
	}

	sorted := append([]StatsRaw(nil), rows...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].HostHash != sorted[j].HostHash {
			return sorted[i].HostHash < sorted[j].HostHash
		}

		if sorted[i].CreatedAt != sorted[j].CreatedAt {
			return sorted[i].CreatedAt > sorted[j].CreatedAt
		}

		return sorted[i].ID > sorted[j].ID
	})

	out := make(map[string]StatsRaw, len(sorted))

	for _, row := range sorted {
		if _, seen := out[row.HostHash]; seen {
			continue
		}

		out[row.HostHash] = row
	}

	return out
}

func computeStatisticsTotals(rows []StatsRaw, lastByHost map[string]StatsRaw) StatisticsTotals {
	uniqueHosts := int64(len(lastByHost))
	healthy := int64(0)

	for _, row := range lastByHost {
		if DeriveHealthy(row) {
			healthy++
		}
	}

	return StatisticsTotals{
		Sessions:    int64(len(rows)),
		UniqueHosts: uniqueHosts,
		HealthyPct:  pctHealthy(healthy, uniqueHosts),
	}
}

func pctHealthy(healthy, uniqueHosts int64) float64 {
	if uniqueHosts == 0 {
		return 0
	}

	return roundPct(100.0 * float64(healthy) / float64(uniqueHosts))
}

func roundPct(value float64) float64 {
	return math.Round(value*10) / 10
}

func normalizePlatformLabel(raw string) string {
	label := strings.ToLower(strings.TrimSpace(raw))
	if label == "" {
		return statsPlatformUnknown
	}

	return label
}

func computeStatisticsPlatforms(lastByHost map[string]StatsRaw) []StatisticsPlatform {
	counts := map[string]int64{}

	for _, row := range lastByHost {
		label := normalizePlatformLabel(row.Platform)
		counts[label]++
	}

	visible := map[string]int64{}

	var otherCount int64

	for label, count := range counts {
		if label == statsPlatformUnknown || count > statsPlatformKAnonymity {
			visible[label] += count

			continue
		}

		otherCount += count
	}

	if otherCount > 0 {
		visible[statsPlatformOther] = otherCount
	}

	totalVisible := int64(len(lastByHost))
	platforms := make([]StatisticsPlatform, 0, len(visible))

	for label, count := range visible {
		platforms = append(platforms, StatisticsPlatform{
			Platform: label,
			Count:    count,
			Pct:      roundPct(100.0 * float64(count) / float64(totalVisible)),
		})
	}

	sort.Slice(platforms, func(i, j int) bool {
		if platforms[i].Count != platforms[j].Count {
			return platforms[i].Count > platforms[j].Count
		}

		return platforms[i].Platform < platforms[j].Platform
	})

	if platforms == nil {
		return []StatisticsPlatform{}
	}

	return platforms
}

func computeStatisticsAreas(rows []StatsRaw) []StatisticsArea {
	areas := make([]StatisticsArea, 0, len(statsAreaOrder))

	for _, spec := range statsAreaOrder {
		area := StatisticsArea{Area: spec.Name}

		for _, row := range rows {
			grade := spec.Grade(row)
			if grade == nil {
				continue
			}

			switch *grade {
			case GradePass:
				area.Pass++
			case GradeWarn:
				area.Warn++
			case GradeFail:
				area.Fail++
			}
		}

		areas = append(areas, area)
	}

	return areas
}

func computeStatisticsDaily(rows []StatsRaw, from, to int64) []StatisticsDaily {
	if from > to {
		return []StatisticsDaily{}
	}

	dayStart := utcDayStartUnix(from)
	endDay := utcDayStartUnix(to)

	buckets := map[int64][]StatsRaw{}

	for _, row := range rows {
		dayTS := utcDayStartUnix(row.CreatedAt)
		if dayTS < dayStart || dayTS > endDay {
			continue
		}

		buckets[dayTS] = append(buckets[dayTS], row)
	}

	daily := make([]StatisticsDaily, 0)

	for ts := dayStart; ts <= endDay; ts += secondsPerDay {
		dayRows := buckets[ts]
		lastByHost := lastRowPerHost(dayRows)
		healthy := int64(0)

		for _, row := range lastByHost {
			if DeriveHealthy(row) {
				healthy++
			}
		}

		daily = append(daily, StatisticsDaily{
			TS:         ts,
			Sessions:   int64(len(dayRows)),
			HealthyPct: pctHealthy(healthy, int64(len(lastByHost))),
		})
	}

	return daily
}

func utcDayStartUnix(ts int64) int64 {
	t := time.Unix(ts, 0).UTC()
	start := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)

	return start.Unix()
}
