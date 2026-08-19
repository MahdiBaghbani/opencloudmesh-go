// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

func TestParseStatisticsDays_DefaultMissingEmptyAndAllowed(t *testing.T) {
	t.Parallel()

	cases := []struct {
		raw  string
		want int
	}{
		{"", 14},
		{"   ", 14},
		{"7", 7},
		{"14", 14},
		{"30", 30},
		{"60", 60},
		{"90", 90},
		{"365", 365},
		{"0", 0},
	}

	for _, tc := range cases {
		got, err := parseStatisticsDays(tc.raw)
		if err != nil {
			t.Fatalf("parseStatisticsDays(%q): %v", tc.raw, err)
		}

		if got != tc.want {
			t.Fatalf("parseStatisticsDays(%q) = %d, want %d", tc.raw, got, tc.want)
		}
	}
}

func TestParseStatisticsDays_InvalidSelector(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{"1", "13", "abc", "-7"} {
		if _, err := parseStatisticsDays(raw); err == nil {
			t.Fatalf("parseStatisticsDays(%q) expected error", raw)
		}
	}
}

func TestHandleStatistics_InvalidDaysSelector400(t *testing.T) {
	t.Parallel()

	h := NewHandler(openHandlerTestStore(t), nil)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/statistics?days=13", nil)
	rec := httptest.NewRecorder()
	h.HandleStatistics(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}

	var payload map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if payload["error"] != statisticsErrInvalidDays {
		t.Fatalf("error = %q, want %q", payload["error"], statisticsErrInvalidDays)
	}
}

func TestHandleStatistics_DefaultDaysAndSchema(t *testing.T) {
	t.Parallel()

	h := NewHandler(openHandlerTestStore(t), nil)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/statistics", nil)
	rec := httptest.NewRecorder()
	h.HandleStatistics(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var payload statisticsResponse
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if payload.Schema != statisticsSchema {
		t.Fatalf("schema = %q, want %q", payload.Schema, statisticsSchema)
	}

	if payload.Window.Days != 14 || payload.Window.Selector != "days=14" {
		t.Fatalf("window = %+v, want days=14 default", payload.Window)
	}

	if payload.DailyOmitted {
		t.Fatal("expected daily series for default window")
	}
}

func TestHandleStatistics_AllTimeDailyOmitted(t *testing.T) {
	t.Parallel()

	h := NewHandler(openHandlerTestStore(t), nil)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/statistics?days=0", nil)
	rec := httptest.NewRecorder()
	h.HandleStatistics(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var payload statisticsResponse
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if !payload.DailyOmitted {
		t.Fatal("expected daily_omitted for all-time")
	}

	if len(payload.Daily) != 0 {
		t.Fatalf("daily len = %d, want 0", len(payload.Daily))
	}
}

func TestHandleStatistics_PrivacyNoHostHashOrRawHost(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	ctx := t.Context()

	pass := validatorcore.GradePass
	rawHost := "peer.example"
	rawHash := "hash-peer-example"

	row := validatorcore.StatsRaw{
		K:              "k-stats-redact",
		HostHash:       rawHash,
		Platform:       "nextcloud",
		GradeDiscovery: &pass,
		CreatedAt:      1_700_000_000,
	}

	if err := store.InsertStatsRaw(ctx, &row); err != nil {
		t.Fatalf("InsertStatsRaw: %v", err)
	}

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/statistics?days=0", nil)
	rec := httptest.NewRecorder()
	h.HandleStatistics(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	body := rec.Body.String()
	if strings.Contains(body, rawHash) {
		t.Fatalf("response must not contain host_hash %q", rawHash)
	}

	if strings.Contains(body, rawHost) {
		t.Fatalf("response must not contain raw host %q", rawHost)
	}

	if strings.Contains(strings.ToLower(body), "host_hash") {
		t.Fatal("response must not expose host_hash field name")
	}

	var payload statisticsResponse
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if payload.Schema != statisticsSchema {
		t.Fatalf("schema = %q, want %q", payload.Schema, statisticsSchema)
	}
}

func TestHandleStatistics_AggregatesHealthyPlatformAndAreas(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	ctx := t.Context()

	pass := validatorcore.GradePass
	warn := validatorcore.GradeWarn

	rows := []validatorcore.StatsRaw{
		{
			K:              "k-stats-agg-1",
			HostHash:       "host-a",
			Platform:       "nextcloud",
			GradeDiscovery: &pass,
			CreatedAt:      1_700_000_000,
		},
		{
			K:              "k-stats-agg-2",
			HostHash:       "host-a",
			Platform:       "nextcloud",
			GradeDiscovery: &warn,
			CreatedAt:      1_700_000_100,
			ID:             2,
		},
		{
			K:              "k-stats-agg-3",
			HostHash:       "host-b",
			Platform:       "nextcloud",
			GradeDiscovery: &pass,
			CreatedAt:      1_700_000_000,
		},
	}

	for i := range rows {
		if err := store.InsertStatsRaw(ctx, &rows[i]); err != nil {
			t.Fatalf("InsertStatsRaw: %v", err)
		}
	}

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/statistics?days=0", nil)
	rec := httptest.NewRecorder()
	h.HandleStatistics(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var payload statisticsResponse
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if payload.Totals.Sessions != 3 {
		t.Fatalf("sessions = %d, want 3", payload.Totals.Sessions)
	}

	if payload.Totals.UniqueHosts != 2 {
		t.Fatalf("unique_hosts = %d, want 2", payload.Totals.UniqueHosts)
	}

	if payload.Totals.HealthyPct != 50.0 {
		t.Fatalf("healthy_pct = %v, want 50.0", payload.Totals.HealthyPct)
	}

	if len(payload.Platforms) != 1 || payload.Platforms[0].Platform != "other" || payload.Platforms[0].Count != 2 {
		t.Fatalf("platforms = %+v, want single other bucket with count 2", payload.Platforms)
	}

	discovery := findStatisticsArea(payload.Areas, "discovery")
	if discovery.Pass != 2 || discovery.Warn != 1 || discovery.Fail != 0 {
		t.Fatalf("discovery area = %+v, want pass=2 warn=1", discovery)
	}
}

func findStatisticsArea(areas []statisticsAreaResponse, name string) statisticsAreaResponse {
	for _, area := range areas {
		if area.Area == name {
			return area
		}
	}

	return statisticsAreaResponse{Area: name}
}
