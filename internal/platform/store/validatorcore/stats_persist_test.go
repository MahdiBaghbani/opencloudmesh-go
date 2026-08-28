// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"strings"
	"testing"
	"time"
)

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
