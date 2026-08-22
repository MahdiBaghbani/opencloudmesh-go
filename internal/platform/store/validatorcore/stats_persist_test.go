// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"strings"
	"testing"
	"time"

	fedcore "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/core"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/statistics"
)

func testStatsHostHasher(t *testing.T) StatsHostHasher {
	t.Helper()

	salt := make([]byte, statistics.RedactionSaltSize)
	for i := range salt {
		salt[i] = byte(i + 1)
	}

	hasher, err := fedcore.New(salt)
	if err != nil {
		t.Fatalf("fedcore.New: %v", err)
	}

	return hasher
}

func seedPassiveComplete(t *testing.T, core *Core, runID, targetOrigin string, optInStats bool) {
	t.Helper()

	ctx := t.Context()
	now := time.Now().Unix()

	row := &TestRun{
		TestRunID:    runID,
		State:        StatePassiveComplete,
		TargetOrigin: targetOrigin,
		TargetHost:   "peer.example",
		OptInStats:   optInStats,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := core.CreatePassiveSession(ctx, row); err != nil {
		t.Fatalf("CreatePassiveSession: %v", err)
	}
}

func seedTerminalStatsRun(t *testing.T, core *Core, runID string, finishedAt int64) {
	t.Helper()

	row := &TestRun{
		TestRunID:    runID,
		State:        StateTerminalPass,
		TargetOrigin: "https://peer.example",
		TargetHost:   "peer.example",
		FinishedAt:   &finishedAt,
		OptInStats:   true,
		CreatedAt:    finishedAt,
		UpdatedAt:    finishedAt,
	}

	if err := core.DB().WithContext(t.Context()).Create(row).Error; err != nil {
		t.Fatalf("seed terminal run: %v", err)
	}
}

func seedEvidenceRow(
	t *testing.T,
	core *Core,
	runID, leg, area, step, reasonCode, severity string,
	affectsGrade bool,
) {
	t.Helper()

	row := &EvidenceRow{
		TestRunID:    runID,
		Leg:          &leg,
		Area:         area,
		Step:         step,
		ReasonCode:   reasonCode,
		Severity:     severity,
		AffectsGrade: affectsGrade,
		CreatedAt:    time.Now().Unix(),
	}

	if err := core.DB().WithContext(t.Context()).Create(row).Error; err != nil {
		t.Fatalf("seed evidence row: %v", err)
	}
}

func TestPersistTerminalStats_OptInWritesRaw(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.SetStatsHostHasher(testStatsHostHasher(t))
	ctx := t.Context()

	runID := "run-stats-opt-in"
	seedPassiveComplete(t, core, runID, "https://Peer.Example:443", true)

	if err := core.StopPassive(ctx, runID); err != nil {
		t.Fatalf("StopPassive: %v", err)
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

	if raw.HostHash == "" {
		t.Fatal("expected host_hash to be set")
	}

	if strings.Contains(raw.HostHash, "peer.example") {
		t.Fatalf("host_hash must not contain raw host, got %q", raw.HostHash)
	}

	if DeriveHealthy(raw) {
		t.Fatal("expected all-null grades to be unhealthy")
	}
}

func TestPersistTerminalStats_IncognitoWritesNothing(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.SetStatsHostHasher(testStatsHostHasher(t))
	ctx := t.Context()

	runID := "run-stats-incognito"
	seedPassiveComplete(t, core, runID, "https://peer.example", false)

	if err := core.StopPassive(ctx, runID); err != nil {
		t.Fatalf("StopPassive: %v", err)
	}

	var rawCount int64
	if err := core.DB().WithContext(ctx).Model(&StatsRaw{}).Count(&rawCount).Error; err != nil {
		t.Fatalf("count stats_raw: %v", err)
	}

	if rawCount != 0 {
		t.Fatalf("stats_raw count = %d, want 0", rawCount)
	}
}

func TestPersistTerminalStats_PermanentOnlyWritesNothing(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.SetStatsHostHasher(testStatsHostHasher(t))
	ctx := t.Context()
	now := time.Now().Unix()
	runID := "run-stats-permanent-only"

	row := &TestRun{
		TestRunID:      runID,
		State:          StatePassiveComplete,
		TargetOrigin:   "https://peer.example",
		TargetHost:     "peer.example",
		OptInStats:     false,
		OptInPermanent: true,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	if err := core.CreatePassiveSession(ctx, row); err != nil {
		t.Fatalf("CreatePassiveSession: %v", err)
	}

	if err := core.StopPassive(ctx, runID); err != nil {
		t.Fatalf("StopPassive: %v", err)
	}

	var rawCount int64
	if err := core.DB().WithContext(ctx).Model(&StatsRaw{}).Count(&rawCount).Error; err != nil {
		t.Fatalf("count stats_raw: %v", err)
	}

	if rawCount != 0 {
		t.Fatalf("stats_raw count = %d, want 0 for permanent-only", rawCount)
	}
}

func TestPersistTerminalStats_PersistedOptInWritesWithoutMemoryFlag(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.SetStatsHostHasher(testStatsHostHasher(t))
	ctx := t.Context()
	now := time.Now().Unix()
	runID := "run-stats-persisted-opt-in"

	row := &TestRun{
		TestRunID:    runID,
		State:        StatePassiveComplete,
		TargetOrigin: "https://peer.example",
		TargetHost:   "peer.example",
		OptInStats:   true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := core.CreatePassiveSession(ctx, row); err != nil {
		t.Fatalf("CreatePassiveSession: %v", err)
	}

	if err := core.StopPassive(ctx, runID); err != nil {
		t.Fatalf("StopPassive: %v", err)
	}

	var rawCount int64
	if err := core.DB().WithContext(ctx).Model(&StatsRaw{}).Count(&rawCount).Error; err != nil {
		t.Fatalf("count stats_raw: %v", err)
	}

	if rawCount != 1 {
		t.Fatalf("stats_raw count = %d, want 1 from persisted opt_in_stats", rawCount)
	}
}

func TestPersistTerminalStats_DerivesSessionKindFromBobUserID(t *testing.T) {
	t.Parallel()

	bobID := "bob-session-kind"

	tests := []struct {
		name      string
		bobUserID *string
		wantKind  string
		wipePII   bool
	}{
		{
			name:      "bob_user_id set persists active_full",
			bobUserID: &bobID,
			wantKind:  SessionKindActiveFull,
			wipePII:   true,
		},
		{
			name:      "bob_user_id unset persists passive_only",
			bobUserID: nil,
			wantKind:  SessionKindPassiveOnly,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			core := openTestCore(t)
			core.SetStatsHostHasher(testStatsHostHasher(t))
			ctx := t.Context()
			now := time.Now().Unix()
			runID := "run-session-kind-" + tt.wantKind

			row := &TestRun{
				TestRunID:    runID,
				State:        StateTerminalPass,
				TargetOrigin: "https://peer.example",
				TargetHost:   "peer.example",
				FinishedAt:   &now,
				OptInStats:   true,
				BobUserID:    tt.bobUserID,
				CreatedAt:    now,
				UpdatedAt:    now,
			}
			if err := core.DB().WithContext(ctx).Create(row).Error; err != nil {
				t.Fatalf("seed terminal run: %v", err)
			}

			if err := core.persistTerminalStats(ctx, runID); err != nil {
				t.Fatalf("persist: %v", err)
			}

			if tt.wipePII {
				if err := core.DB().WithContext(ctx).Model(&TestRun{}).
					Where("test_run_id = ?", runID).
					Updates(map[string]any{colBobUserID: nil}).Error; err != nil {
					t.Fatalf("wipe bob_user_id: %v", err)
				}

				wiped, err := core.GetTestRun(ctx, runID)
				if err != nil {
					t.Fatalf("GetTestRun after wipe: %v", err)
				}

				if wiped.BobUserID != nil {
					t.Fatalf("bob_user_id = %v after wipe, want nil", wiped.BobUserID)
				}
			}

			var raw StatsRaw
			if err := core.DB().WithContext(ctx).First(&raw).Error; err != nil {
				t.Fatalf("load stats_raw: %v", err)
			}

			if raw.SessionKind != tt.wantKind {
				t.Fatalf("session_kind = %q, want %q", raw.SessionKind, tt.wantKind)
			}
		})
	}
}

func TestHashHostForTestRun_DeterministicAcrossEquivalentOrigins(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.SetStatsHostHasher(testStatsHostHasher(t))

	rows := []*TestRun{
		{TargetOrigin: "https://Peer.Example:443"},
		{TargetOrigin: "https://peer.example"},
	}

	first, err := core.hashHostForTestRun(rows[0])
	if err != nil {
		t.Fatalf("hash first: %v", err)
	}

	second, err := core.hashHostForTestRun(rows[1])
	if err != nil {
		t.Fatalf("hash second: %v", err)
	}

	if first != second {
		t.Fatalf("expected equivalent origins to hash identically: %q vs %q", first, second)
	}
}

func TestPersistTerminalStats_DerivesFromEvidenceFold(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.SetStatsHostHasher(testStatsHostHasher(t))
	ctx := t.Context()
	now := time.Now().Unix()
	pass := GradePass

	runID := "run-stats-healthy"
	row := &TestRun{
		TestRunID:    runID,
		State:        StatePassiveComplete,
		TargetOrigin: "https://peer.example",
		TargetHost:   "peer.example",
		OptInStats:   true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := core.CreatePassiveSession(ctx, row); err != nil {
		t.Fatalf("CreatePassiveSession: %v", err)
	}

	seedEvidenceRow(t, core, runID, evidenceLegPassive, SpecificationAreaDiscovery, "fetch", "discovery_ok", pass, true)

	if err := core.StopPassive(ctx, runID); err != nil {
		t.Fatalf("StopPassive: %v", err)
	}

	var raw StatsRaw
	if err := core.DB().WithContext(ctx).First(&raw).Error; err != nil {
		t.Fatalf("load stats_raw: %v", err)
	}

	if raw.GradeDiscovery == nil || *raw.GradeDiscovery != GradePass {
		t.Fatalf("grade_discovery = %v, want pass from evidence", raw.GradeDiscovery)
	}

	if !DeriveHealthy(raw) {
		t.Fatal("expected pass grade snapshot to be healthy")
	}
}

func TestPersistTerminalStats_OverallGradeDoesNotDriveHealthy(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.SetStatsHostHasher(testStatsHostHasher(t))
	ctx := t.Context()
	now := time.Now().Unix()

	runID := "run-stats-overall-only"
	row := &TestRun{
		TestRunID:    runID,
		State:        StatePassiveComplete,
		TargetOrigin: "https://peer.example",
		TargetHost:   "peer.example",
		OptInStats:   true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := core.CreatePassiveSession(ctx, row); err != nil {
		t.Fatalf("CreatePassiveSession: %v", err)
	}

	if err := core.StopPassive(ctx, runID); err != nil {
		t.Fatalf("StopPassive: %v", err)
	}

	var raw StatsRaw
	if err := core.DB().WithContext(ctx).First(&raw).Error; err != nil {
		t.Fatalf("load stats_raw: %v", err)
	}

	if DeriveHealthy(raw) {
		t.Fatal("overall_grade on test_run must not substitute for area grades in DeriveHealthy")
	}
}

func TestSweepPassiveCompleteTTL_PersistsOptedInStatsAfterTransactionCommit(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.SetStatsHostHasher(testStatsHostHasher(t))
	core.sessionCfg = SessionConfig{
		InFlightPassiveLimit:      10,
		PassiveCompleteTTLSeconds: 60,
	}

	ctx := t.Context()
	stale := time.Now().Add(-2 * time.Minute).Unix()
	pass := GradePass
	runID := "run-pc-sweep-stats"

	row := &TestRun{
		TestRunID:    runID,
		IsActive:     false,
		State:        StatePassiveComplete,
		TargetOrigin: "https://peer.example",
		TargetHost:   "peer.example",
		OptInStats:   true,
		CreatedAt:    stale,
		UpdatedAt:    stale,
	}

	if err := core.DB().WithContext(ctx).Create(row).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	seedEvidenceRow(t, core, runID, evidenceLegPassive, SpecificationAreaDiscovery, "fetch", "discovery_ok", pass, true)

	if err := core.sweepPassiveCompleteTTL(ctx); err != nil {
		t.Fatalf("sweepPassiveCompleteTTL: %v", err)
	}

	var rawCount int64
	if err := core.DB().WithContext(ctx).Model(&StatsRaw{}).Count(&rawCount).Error; err != nil {
		t.Fatalf("count stats_raw: %v", err)
	}

	if rawCount != 1 {
		t.Fatalf("stats_raw count = %d, want 1 after TTL terminalization", rawCount)
	}

	var raw StatsRaw
	if err := core.DB().WithContext(ctx).First(&raw).Error; err != nil {
		t.Fatalf("load stats_raw: %v", err)
	}

	if !DeriveHealthy(raw) {
		t.Fatal("expected healthy stats row from discovery evidence")
	}
}

func TestPruneStats_RemovesStaleRaw(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.SetStatsHostHasher(testStatsHostHasher(t))
	ctx := t.Context()

	pass := GradePass
	now := time.Now().Unix()
	staleTS := now - 10*24*3600
	recentTS := now

	staleRaw := StatsRaw{
		K:              "k-prune-stale",
		HostHash:       "hash-prune",
		SessionKind:    SessionKindPassiveOnly,
		GradeDiscovery: &pass,
		CreatedAt:      staleTS,
	}
	recentRaw := StatsRaw{
		K:              "k-prune-recent",
		HostHash:       "hash-prune",
		SessionKind:    SessionKindPassiveOnly,
		GradeDiscovery: &pass,
		CreatedAt:      recentTS,
	}

	for _, row := range []StatsRaw{staleRaw, recentRaw} {
		if err := core.InsertStatsRaw(ctx, &row); err != nil {
			t.Fatalf("InsertStatsRaw: %v", err)
		}
	}

	if err := core.PruneStats(ctx, 7); err != nil {
		t.Fatalf("PruneStats: %v", err)
	}

	var rawCount int64
	if err := core.DB().WithContext(ctx).Model(&StatsRaw{}).Count(&rawCount).Error; err != nil {
		t.Fatalf("count stats_raw: %v", err)
	}

	if rawCount != 1 {
		t.Fatalf("stats_raw count = %d, want 1 after prune", rawCount)
	}

	var surviving StatsRaw
	if err := core.DB().WithContext(ctx).First(&surviving).Error; err != nil {
		t.Fatalf("load surviving stats_raw: %v", err)
	}

	if surviving.K != "k-prune-recent" {
		t.Fatalf("surviving k = %q, want k-prune-recent", surviving.K)
	}
}
