// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

const (
	statisticsSchema              = "federation_tester_statistics.v1"
	statisticsDefaultDays         = 14
	statisticsErrInvalidDays      = "invalid_days_selector"
	statisticsAllowedDaysSelector = "7|14|30|60|90|365|0"
)

var statisticsAllowedDays = map[int]struct{}{
	0:   {},
	7:   {},
	14:  {},
	30:  {},
	60:  {},
	90:  {},
	365: {},
}

type statisticsWindowResponse struct {
	Days     int    `json:"days"`
	From     int64  `json:"from"`
	To       int64  `json:"to"`
	Selector string `json:"selector"`
}

type statisticsTotalsResponse struct {
	Sessions    int64   `json:"sessions"`
	UniqueHosts int64   `json:"unique_hosts"` //nolint:tagliatelle // federation_tester_statistics.v1 locked schema
	HealthyPct  float64 `json:"healthy_pct"`  //nolint:tagliatelle // federation_tester_statistics.v1 locked schema
}

type statisticsPlatformResponse struct {
	Platform string  `json:"platform"`
	Count    int64   `json:"count"`
	Pct      float64 `json:"pct"`
}

type statisticsAreaResponse struct {
	Area string `json:"area"`
	Pass int64  `json:"pass"`
	Warn int64  `json:"warn"`
	Fail int64  `json:"fail"`
}

type statisticsDailyResponse struct {
	TS         int64   `json:"ts"`
	Sessions   int64   `json:"sessions"`
	HealthyPct float64 `json:"healthy_pct"` //nolint:tagliatelle // federation_tester_statistics.v1 locked schema
}

type statisticsResponse struct {
	Schema       string                       `json:"schema"`
	Window       statisticsWindowResponse     `json:"window"`
	Totals       statisticsTotalsResponse     `json:"totals"`
	Platforms    []statisticsPlatformResponse `json:"platforms"`
	Areas        []statisticsAreaResponse     `json:"areas"`
	Daily        []statisticsDailyResponse    `json:"daily"`
	DailyOmitted bool                         `json:"daily_omitted,omitempty"` //nolint:tagliatelle // federation_tester_statistics.v1 locked schema
}

// HandleStatistics serves GET /api/statistics for anonymous aggregate reads.
func (h *Handler) HandleStatistics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)

		return
	}

	if h.store == nil {
		writeJSONError(w, h.log, http.StatusInternalServerError, "store_unavailable", "validator store is not configured")

		return
	}

	days, err := parseStatisticsDays(r.URL.Query().Get("days"))
	if err != nil {
		writeJSONError(w, h.log, http.StatusBadRequest, statisticsErrInvalidDays, err.Error())

		return
	}

	window := validatorcore.BuildStatisticsWindow(days, time.Now())

	stats, err := h.store.QueryFederationTesterStatistics(r.Context(), window)
	if err != nil {
		writeJSONError(w, h.log, http.StatusInternalServerError, "statistics_query_failed", "failed to load statistics")

		return
	}

	writeJSON(w, h.log, http.StatusOK, toStatisticsResponse(stats))
}

func parseStatisticsDays(raw string) (int, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return statisticsDefaultDays, nil
	}

	days, err := strconv.Atoi(trimmed)
	if err != nil {
		return 0, invalidDaysSelectorError()
	}

	if _, ok := statisticsAllowedDays[days]; !ok {
		return 0, invalidDaysSelectorError()
	}

	return days, nil
}

func invalidDaysSelectorError() error {
	return errStatisticsDaysSelector
}

var errStatisticsDaysSelector = statisticsDaysSelectorError("days must be one of " + statisticsAllowedDaysSelector)

type statisticsDaysSelectorError string

func (e statisticsDaysSelectorError) Error() string {
	return string(e)
}

func toStatisticsResponse(stats *validatorcore.FederationTesterStatistics) statisticsResponse {
	if stats == nil {
		return statisticsResponse{
			Schema:    statisticsSchema,
			Platforms: []statisticsPlatformResponse{},
			Areas:     []statisticsAreaResponse{},
			Daily:     []statisticsDailyResponse{},
		}
	}

	platforms := make([]statisticsPlatformResponse, 0, len(stats.Platforms))
	for _, item := range stats.Platforms {
		platforms = append(platforms, statisticsPlatformResponse{
			Platform: item.Platform,
			Count:    item.Count,
			Pct:      item.Pct,
		})
	}

	areas := make([]statisticsAreaResponse, 0, len(stats.Areas))
	for _, item := range stats.Areas {
		areas = append(areas, statisticsAreaResponse{
			Area: item.Area,
			Pass: item.Pass,
			Warn: item.Warn,
			Fail: item.Fail,
		})
	}

	daily := make([]statisticsDailyResponse, 0, len(stats.Daily))
	for _, item := range stats.Daily {
		daily = append(daily, statisticsDailyResponse{
			TS:         item.TS,
			Sessions:   item.Sessions,
			HealthyPct: item.HealthyPct,
		})
	}

	return statisticsResponse{
		Schema: statisticsSchema,
		Window: statisticsWindowResponse{
			Days:     stats.Window.Days,
			From:     stats.Window.From,
			To:       stats.Window.To,
			Selector: stats.Window.Selector,
		},
		Totals: statisticsTotalsResponse{
			Sessions:    stats.Totals.Sessions,
			UniqueHosts: stats.Totals.UniqueHosts,
			HealthyPct:  stats.Totals.HealthyPct,
		},
		Platforms:    platforms,
		Areas:        areas,
		Daily:        daily,
		DailyOmitted: stats.DailyOmitted,
	}
}
