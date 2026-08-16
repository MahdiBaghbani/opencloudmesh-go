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

func seedPassiveComplete(t *testing.T, core *Core, runID, targetOrigin, targetHost string) {
	t.Helper()

	ctx := t.Context()
	now := time.Now().Unix()

	row := &TestRun{
		TestRunID:    runID,
		State:        StatePassiveComplete,
		SessionKind:  SessionKindPassiveOnly,
		TargetOrigin: targetOrigin,
		TargetHost:   targetHost,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := core.CreatePassiveSession(ctx, row); err != nil {
		t.Fatalf("CreatePassiveSession: %v", err)
	}
}

func TestPersistTerminalStats_OptInWritesRawAndAggregate(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.SetStatsHostHasher(testStatsHostHasher(t))
	ctx := t.Context()

	runID := "run-stats-opt-in"
	seedPassiveComplete(t, core, runID, "https://Peer.Example:443", "peer.example")
	core.SetSessionContribute(runID, true)

	if err := core.StopPassiveComplete(ctx, runID); err != nil {
		t.Fatalf("StopPassiveComplete: %v", err)
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

	var agg StatsAggregate
	if err := core.DB().WithContext(ctx).First(&agg, "host_hash = ?", raw.HostHash).Error; err != nil {
		t.Fatalf("load stats_aggregate: %v", err)
	}

	if agg.TotalSessions != 1 {
		t.Fatalf("total_sessions = %d, want 1", agg.TotalSessions)
	}

	if agg.HealthySessions != 0 {
		t.Fatalf("healthy_sessions = %d, want 0 for all-null grades", agg.HealthySessions)
	}
}

func TestPersistTerminalStats_IncognitoWritesNothing(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.SetStatsHostHasher(testStatsHostHasher(t))
	ctx := t.Context()

	runID := "run-stats-incognito"
	seedPassiveComplete(t, core, runID, "https://peer.example", "peer.example")

	if err := core.StopPassiveComplete(ctx, runID); err != nil {
		t.Fatalf("StopPassiveComplete: %v", err)
	}

	var rawCount int64
	if err := core.DB().WithContext(ctx).Model(&StatsRaw{}).Count(&rawCount).Error; err != nil {
		t.Fatalf("count stats_raw: %v", err)
	}

	if rawCount != 0 {
		t.Fatalf("stats_raw count = %d, want 0", rawCount)
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

func TestPersistTerminalStats_DerivesHealthyFromTerminalSnapshotHook(t *testing.T) {
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
		SessionKind:  SessionKindPassiveOnly,
		TargetOrigin: "https://peer.example",
		TargetHost:   "peer.example",
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := core.CreatePassiveSession(ctx, row); err != nil {
		t.Fatalf("CreatePassiveSession: %v", err)
	}

	core.SetSessionContribute(runID, true)
	core.SetTerminalStatsSnapshot(runID, StatsSnapshot{GradeDiscovery: &pass})

	if err := core.StopPassiveComplete(ctx, runID); err != nil {
		t.Fatalf("StopPassiveComplete: %v", err)
	}

	var raw StatsRaw
	if err := core.DB().WithContext(ctx).First(&raw).Error; err != nil {
		t.Fatalf("load stats_raw: %v", err)
	}

	if raw.GradeDiscovery == nil || *raw.GradeDiscovery != GradePass {
		t.Fatalf("grade_discovery = %v, want pass from terminal snapshot overlay", raw.GradeDiscovery)
	}

	if !DeriveHealthy(raw) {
		t.Fatal("expected pass grade snapshot to be healthy")
	}

	var agg StatsAggregate
	if err := core.DB().WithContext(ctx).First(&agg, "host_hash = ?", raw.HostHash).Error; err != nil {
		t.Fatalf("load aggregate: %v", err)
	}

	if agg.HealthySessions != 1 {
		t.Fatalf("healthy_sessions = %d, want 1", agg.HealthySessions)
	}

	if !agg.LastHealthy {
		t.Fatal("expected last_healthy true from pass-grade snapshot")
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
		SessionKind:  SessionKindPassiveOnly,
		TargetOrigin: "https://peer.example",
		TargetHost:   "peer.example",
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := core.CreatePassiveSession(ctx, row); err != nil {
		t.Fatalf("CreatePassiveSession: %v", err)
	}

	core.SetSessionContribute(runID, true)

	if err := core.StopPassiveComplete(ctx, runID); err != nil {
		t.Fatalf("StopPassiveComplete: %v", err)
	}

	var raw StatsRaw
	if err := core.DB().WithContext(ctx).First(&raw).Error; err != nil {
		t.Fatalf("load stats_raw: %v", err)
	}

	if DeriveHealthy(raw) {
		t.Fatal("overall_grade on test_run must not substitute for area grades in DeriveHealthy")
	}

	var agg StatsAggregate
	if err := core.DB().WithContext(ctx).First(&agg, "host_hash = ?", raw.HostHash).Error; err != nil {
		t.Fatalf("load aggregate: %v", err)
	}

	if agg.HealthySessions != 0 {
		t.Fatalf("healthy_sessions = %d, want 0 without area grades", agg.HealthySessions)
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
		SessionKind:  SessionKindPassiveOnly,
		TargetOrigin: "https://peer.example",
		TargetHost:   "peer.example",
		CreatedAt:    stale,
		UpdatedAt:    stale,
	}

	if err := core.DB().WithContext(ctx).Create(row).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	core.SetSessionContribute(runID, true)
	core.SetTerminalStatsSnapshot(runID, StatsSnapshot{GradeDiscovery: &pass})

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
		t.Fatal("expected healthy stats row from terminal snapshot overlay")
	}
}

func TestPruneStats_RemovesStaleRawAndRebuildsAggregate(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.SetStatsHostHasher(testStatsHostHasher(t))
	ctx := t.Context()

	pass := GradePass
	now := time.Now().Unix()
	staleTS := now - 10*24*3600
	recentTS := now

	staleRaw := StatsRaw{
		HostHash:       "hash-prune",
		SessionKind:    SessionKindPassiveOnly,
		GradeDiscovery: &pass,
		CreatedAt:      staleTS,
	}
	recentRaw := StatsRaw{
		HostHash:       "hash-prune",
		SessionKind:    SessionKindPassiveOnly,
		GradeDiscovery: &pass,
		CreatedAt:      recentTS,
	}

	for _, row := range []StatsRaw{staleRaw, recentRaw} {
		if err := core.InsertStatsRaw(ctx, &row); err != nil {
			t.Fatalf("InsertStatsRaw: %v", err)
		}

		if err := core.IncrementStatsAggregate(ctx, &row); err != nil {
			t.Fatalf("IncrementStatsAggregate: %v", err)
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

	var agg StatsAggregate
	if err := core.DB().WithContext(ctx).First(&agg, "host_hash = ?", "hash-prune").Error; err != nil {
		t.Fatalf("load aggregate: %v", err)
	}

	if agg.TotalSessions != 1 {
		t.Fatalf("total_sessions = %d, want 1 after rebuild", agg.TotalSessions)
	}
}
