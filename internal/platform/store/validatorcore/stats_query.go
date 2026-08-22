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
	// statsPlatformKAnonymity is the unique-host threshold for published
	// totals, per-area, per-day, named-platform, and other groups. A group
	// is kept when it has at least this many unique hosts. The unknown
	// platform label stays visible and is not counted toward other groups.
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
		var minCreated int64

		if minErr := c.db.WithContext(ctx).
			Model(&StatsRaw{}).
			Select("COALESCE(MIN(created_at), 0)").
			Scan(&minCreated).Error; minErr != nil {
			return nil, fmt.Errorf("validatorcore: min stats_raw created_at: %w", minErr)
		}

		window.From = minCreated
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
	published := publishedPlatformCounts(countHostsByPlatform(lastByHost))
	visibleLast := lastHostsPublishedInAggregates(lastByHost, published)
	uniqueHosts := int64(len(visibleLast))

	if uniqueHosts < statsPlatformKAnonymity {
		return StatisticsTotals{}
	}

	healthy := countHealthyHosts(visibleLast)
	visibleRows := rowsForVisibleHosts(rows, visibleLast)

	return StatisticsTotals{
		Sessions:    int64(len(visibleRows)),
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
	visible := publishedPlatformCounts(countHostsByPlatform(lastByHost))
	totalVisible := sumInt64Values(visible)
	platforms := make([]StatisticsPlatform, 0, len(visible))

	for label, count := range visible {
		platforms = append(platforms, StatisticsPlatform{
			Platform: label,
			Count:    count,
			Pct:      platformSharePct(count, totalVisible),
		})
	}

	sort.Slice(platforms, func(i, j int) bool {
		if platforms[i].Count != platforms[j].Count {
			return platforms[i].Count > platforms[j].Count
		}

		return platforms[i].Platform < platforms[j].Platform
	})

	return platforms
}

func computeStatisticsAreas(rows []StatsRaw) []StatisticsArea {
	lastByHost := lastRowPerHost(rows)
	published := publishedPlatformCounts(countHostsByPlatform(lastByHost))
	visibleLast := lastHostsPublishedInAggregates(lastByHost, published)
	visibleRows := rowsForVisibleHosts(rows, visibleLast)
	areas := make([]StatisticsArea, 0, len(statsAreaOrder))

	for _, spec := range statsAreaOrder {
		area := StatisticsArea{Area: spec.Name}
		if uniqueHostsWithGrade(visibleRows, spec.Grade) < statsPlatformKAnonymity {
			areas = append(areas, area)

			continue
		}

		for _, row := range visibleRows {
			addAreaGrade(&area, spec.Grade(row))
		}

		areas = append(areas, area)
	}

	return areas
}

func computeStatisticsDaily(rows []StatsRaw, from, to int64) []StatisticsDaily {
	if from > to {
		return []StatisticsDaily{}
	}

	lastByHost := lastRowPerHost(rows)
	published := publishedPlatformCounts(countHostsByPlatform(lastByHost))
	visibleLast := lastHostsPublishedInAggregates(lastByHost, published)
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
		daily = append(daily, statisticsDailyBucket(ts, buckets[ts], visibleLast))
	}

	return daily
}

func countHostsByPlatform(lastByHost map[string]StatsRaw) map[string]int64 {
	counts := map[string]int64{}

	for _, row := range lastByHost {
		counts[normalizePlatformLabel(row.Platform)]++
	}

	return counts
}

func publishedPlatformCounts(counts map[string]int64) map[string]int64 {
	visible := map[string]int64{}

	var otherCount int64

	for label, count := range counts {
		if label == statsPlatformUnknown || count >= statsPlatformKAnonymity {
			visible[label] += count

			continue
		}

		otherCount += count
	}

	if otherCount >= statsPlatformKAnonymity {
		visible[statsPlatformOther] = otherCount
	}

	return visible
}

func countsTowardAggregates(row StatsRaw, published map[string]int64) bool {
	label := normalizePlatformLabel(row.Platform)
	if label == statsPlatformUnknown {
		return false
	}

	if _, named := published[label]; named {
		return true
	}

	_, otherVisible := published[statsPlatformOther]

	return otherVisible
}

func lastHostsPublishedInAggregates(
	lastByHost map[string]StatsRaw,
	published map[string]int64,
) map[string]StatsRaw {
	visible := make(map[string]StatsRaw, len(lastByHost))

	for hash, row := range lastByHost {
		if countsTowardAggregates(row, published) {
			visible[hash] = row
		}
	}

	return visible
}

// rowsForVisibleHosts keeps a historical row only when its host is visible
// by latest membership. Visibility is a host-level property: a suppressed
// host cannot leak older rows from any platform into totals, areas, or days.
func rowsForVisibleHosts(rows []StatsRaw, visibleLast map[string]StatsRaw) []StatsRaw {
	visible := make([]StatsRaw, 0, len(rows))

	for _, row := range rows {
		if _, ok := visibleLast[row.HostHash]; ok {
			visible = append(visible, row)
		}
	}

	return visible
}

func countHealthyHosts(lastByHost map[string]StatsRaw) int64 {
	var healthy int64

	for _, row := range lastByHost {
		if DeriveHealthy(row) {
			healthy++
		}
	}

	return healthy
}

func uniqueHostsWithGrade(rows []StatsRaw, gradeOf func(StatsRaw) *string) int64 {
	seen := map[string]struct{}{}

	for _, row := range rows {
		if gradeOf(row) == nil {
			continue
		}

		seen[row.HostHash] = struct{}{}
	}

	return int64(len(seen))
}

func addAreaGrade(area *StatisticsArea, grade *string) {
	if area == nil || grade == nil {
		return
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

func statisticsDailyBucket(ts int64, dayRows []StatsRaw, visibleLast map[string]StatsRaw) StatisticsDaily {
	visibleRows := rowsForVisibleHosts(dayRows, visibleLast)
	lastVisible := lastRowPerHost(visibleRows)
	uniqueHosts := int64(len(lastVisible))

	if uniqueHosts < statsPlatformKAnonymity {
		return StatisticsDaily{TS: ts}
	}

	return StatisticsDaily{
		TS:         ts,
		Sessions:   int64(len(visibleRows)),
		HealthyPct: pctHealthy(countHealthyHosts(lastVisible), uniqueHosts),
	}
}

func sumInt64Values(values map[string]int64) int64 {
	var total int64

	for _, value := range values {
		total += value
	}

	return total
}

func platformSharePct(count, total int64) float64 {
	if total == 0 {
		return 0
	}

	return roundPct(100.0 * float64(count) / float64(total))
}

func utcDayStartUnix(ts int64) int64 {
	t := time.Unix(ts, 0).UTC()
	start := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)

	return start.Unix()
}
