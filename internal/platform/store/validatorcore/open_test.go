// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/sqlitecore"
)

func TestAttach_CreatesValidatorSchemaOnSharedHandle(t *testing.T) {
	t.Parallel()

	sqlCore, err := sqlitecore.Open(t.TempDir())
	if err != nil {
		t.Fatalf("sqlitecore.Open: %v", err)
	}

	t.Cleanup(func() {
		if closeErr := sqlCore.Close(); closeErr != nil {
			t.Errorf("sqlitecore.Close: %v", closeErr)
		}
	})

	core, err := Attach(sqlCore.DB(), DefaultSessionConfig())
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}

	for _, name := range []string{
		"test_run",
		"share_correlation",
		"stats_raw",
		"report_exchange",
		"evidence_row",
		"dispatch_reservation",
		"validator_schema",
	} {
		if !core.DB().Migrator().HasTable(name) {
			t.Fatalf("Attach must create validator table %q", name)
		}
	}
}

func TestAttachWithStatsHasher_ReopenHealsStatsBeforeTombstone(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	id := "run-reopen-heal-before-wipe"
	seedClosedOptedInExpiredPermanent(t, dir, id)

	second, openErr := sqlitecore.Open(dir)
	if openErr != nil {
		t.Fatalf("sqlitecore.Open second: %v", openErr)
	}

	t.Cleanup(func() {
		if closeErr := second.Close(); closeErr != nil {
			t.Errorf("sqlitecore.Close second: %v", closeErr)
		}
	})

	hasher := testStatsHostHasher(t)

	core, attachErr := AttachWithStatsHasher(second.DB(), retentionSweepSessionConfig(30), hasher)
	if attachErr != nil {
		t.Fatalf("AttachWithStatsHasher: %v", attachErr)
	}

	requireHealedThenTombstoned(t, core, id)
}

func seedClosedOptedInExpiredPermanent(t *testing.T, dir, id string) {
	t.Helper()

	ctx := t.Context()
	now := time.Now().Unix()
	finished := now - 3600
	expires := now - 60

	first, openErr := sqlitecore.Open(dir)
	if openErr != nil {
		t.Fatalf("sqlitecore.Open first: %v", openErr)
	}

	if schemaErr := ApplyValidatorSchema(first.DB()); schemaErr != nil {
		t.Fatalf("ApplyValidatorSchema: %v", schemaErr)
	}

	seeder := NewCore(first.DB())
	seedExpiredPermanentRun(t, seeder.DB(), ctx, id, finished, expires)
	mustExec(t, seeder.DB(), "UPDATE test_run SET opt_in_stats = 1 WHERE test_run_id = '"+id+"'")
	seedEvidenceRow(
		t,
		seeder,
		id,
		evidenceLegPassive,
		SpecificationAreaDiscovery,
		"request",
		"probed",
		GradePass,
		true,
	)

	if closeErr := first.Close(); closeErr != nil {
		t.Fatalf("sqlitecore.Close first: %v", closeErr)
	}
}

func requireHealedThenTombstoned(t *testing.T, core *Core, id string) {
	t.Helper()

	requireStatsWrittenAt(t, core, id, true)

	if count := countStatsRaw(t, core); count != 1 {
		t.Fatalf("stats_raw count = %d, want 1 (heal must land before PII wipe)", count)
	}

	var raw StatsRaw
	if loadErr := core.DB().WithContext(t.Context()).First(&raw).Error; loadErr != nil {
		t.Fatalf("load healed stats_raw: %v", loadErr)
	}

	if raw.HostHash == "" {
		t.Fatal("healed host_hash is empty, want a hash from the pre-wipe origin")
	}

	if raw.GradeDiscovery == nil || *raw.GradeDiscovery != GradePass {
		t.Fatalf(
			"healed grade_discovery = %v, want %q from evidence read before tombstone",
			raw.GradeDiscovery,
			GradePass,
		)
	}

	got, getErr := core.GetTestRun(t.Context(), id)
	if getErr != nil {
		t.Fatalf("GetTestRun: %v (parent must survive as a tombstone)", getErr)
	}

	assertHardExpiryTombstone(t, got)
	assertChildRowCount(t, core.DB(), "evidence_row", id, 0)
}

func TestPruneTerminalRetention_PrunesStatsRaw(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.SetSessionConfig(SessionConfig{TerminalRetentionDays: 30})

	ctx := t.Context()
	now := time.Now().Unix()
	pass := GradePass
	hostHash := "host-retention"

	staleRaw := StatsRaw{
		K:              "k-retention-stale",
		HostHash:       hostHash,
		SessionKind:    SessionKindPassiveOnly,
		Platform:       "Stale",
		GradeDiscovery: new(pass),
		CreatedAt:      now - int64(60*24*3600),
	}

	recentRaw := StatsRaw{
		K:              "k-retention-recent",
		HostHash:       hostHash,
		SessionKind:    SessionKindActiveFull,
		Platform:       "Recent",
		GradeDiscovery: new(pass),
		CreatedAt:      now - 3600,
	}

	for _, row := range []StatsRaw{staleRaw, recentRaw} {
		if err := core.InsertStatsRaw(ctx, &row); err != nil {
			t.Fatalf("insert stats_raw: %v", err)
		}
	}

	staleFinished := now - int64(60*24*3600)
	recentFinished := now - 3600

	for _, row := range []TestRun{
		{
			TestRunID:  "run-stale-terminal",
			State:      StateTerminalFail,
			TargetHost: "stale.example",
			FinishedAt: &staleFinished,
			CreatedAt:  staleFinished,
			UpdatedAt:  staleFinished,
		},
		{
			TestRunID:  "run-recent-terminal",
			State:      StateTerminalPass,
			TargetHost: "recent.example",
			FinishedAt: &recentFinished,
			CreatedAt:  recentFinished,
			UpdatedAt:  recentFinished,
		},
	} {
		if err := core.DB().WithContext(ctx).Create(&row).Error; err != nil {
			t.Fatalf("seed terminal session: %v", err)
		}
	}

	if err := core.pruneTerminalRetention(ctx, 30); err != nil {
		t.Fatalf("pruneTerminalRetention: %v", err)
	}

	var rawCount int64
	if err := core.DB().WithContext(ctx).Model(&StatsRaw{}).Count(&rawCount).Error; err != nil {
		t.Fatalf("count stats_raw: %v", err)
	}

	if rawCount != 1 {
		t.Fatalf("stats_raw rows = %d, want 1 after retention prune", rawCount)
	}

	var liveTerminalCount int64
	if err := core.DB().WithContext(ctx).Model(&TestRun{}).
		Where("state IN ? AND harvested_at IS NULL", []string{StateTerminalPass, StateTerminalFail}).
		Count(&liveTerminalCount).Error; err != nil {
		t.Fatalf("count live terminal sessions: %v", err)
	}

	if liveTerminalCount != 1 {
		t.Fatalf("non-tombstoned terminal test_run rows = %d, want 1 after retention prune", liveTerminalCount)
	}

	assertRunHardDeleted(t, core, core.DB(), "run-stale-terminal")
}

func TestPruneTerminalRetention_SparesPermanentReports(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	now := time.Now().Unix()
	staleFinished := now - int64(60*24*3600)
	futureExpires := staleFinished + 90*SecondsPerDay
	knownHarvested := now - int64(10*24*3600)
	forever := RetentionTierForever
	tier90 := RetentionTier90
	knownReason := HarvestReasonExpired
	timeoutReason := ReasonReverseShareTimeout

	foreverID := "run-permanent-forever"
	tier90ID := "run-permanent-90"
	tombstonedID := "run-permanent-tombstoned"
	stalePassID := "run-nonpermanent-pass"
	staleFailID := "run-nonpermanent-fail"
	staleInterruptedID := "run-nonpermanent-interrupted"

	for _, row := range []TestRun{
		{
			TestRunID:      foreverID,
			State:          StateTerminalPass,
			TargetHost:     "forever.example",
			FinishedAt:     &staleFinished,
			OptInPermanent: true,
			RetentionTier:  &forever,
			CreatedAt:      staleFinished,
			UpdatedAt:      staleFinished,
		},
		{
			TestRunID:      tier90ID,
			State:          StateTerminalPass,
			TargetHost:     "ninety.example",
			FinishedAt:     &staleFinished,
			OptInPermanent: true,
			RetentionTier:  &tier90,
			ExpiresAt:      &futureExpires,
			CreatedAt:      staleFinished,
			UpdatedAt:      staleFinished,
		},
		{
			TestRunID:      tombstonedID,
			State:          StateTerminalFail,
			TargetHost:     "tombstone.example",
			FinishedAt:     &staleFinished,
			OptInPermanent: true,
			HarvestedAt:    &knownHarvested,
			HarvestReason:  &knownReason,
			CreatedAt:      staleFinished,
			UpdatedAt:      staleFinished,
		},
		{
			TestRunID:  stalePassID,
			State:      StateTerminalPass,
			TargetHost: "stale-pass.example",
			FinishedAt: &staleFinished,
			CreatedAt:  staleFinished,
			UpdatedAt:  staleFinished,
		},
		{
			TestRunID:  staleFailID,
			State:      StateTerminalFail,
			TargetHost: "stale-fail.example",
			FinishedAt: &staleFinished,
			CreatedAt:  staleFinished,
			UpdatedAt:  staleFinished,
		},
		{
			TestRunID:      staleInterruptedID,
			State:          StateInterrupted,
			TargetHost:     "stale-interrupted.example",
			TerminalReason: &timeoutReason,
			FinishedAt:     &staleFinished,
			CreatedAt:      staleFinished,
			UpdatedAt:      staleFinished,
		},
	} {
		if err := core.DB().WithContext(ctx).Create(&row).Error; err != nil {
			t.Fatalf("seed %s: %v", row.TestRunID, err)
		}
	}

	seedRunChildSet(t, core.DB(), staleInterruptedID)
	seedExpiryChildRows(t, core.DB(), stalePassID)
	seedExpiryChildRows(t, core.DB(), staleFailID)

	if err := core.pruneTerminalRetention(ctx, 30); err != nil {
		t.Fatalf("pruneTerminalRetention: %v", err)
	}

	assertNoTombstone(t, core, foreverID, StateTerminalPass)
	assertNoTombstone(t, core, tier90ID, StateTerminalPass)
	assertRunHardDeleted(t, core, core.DB(), stalePassID)
	assertRunHardDeleted(t, core, core.DB(), staleFailID)
	assertNoTombstone(t, core, staleInterruptedID, StateInterrupted)
	assertChildRowCount(t, core.DB(), "report_exchange", staleInterruptedID, 1)
	assertChildRowCount(t, core.DB(), "evidence_row", staleInterruptedID, 1)
	assertChildRowCount(t, core.DB(), "dispatch_reservation", staleInterruptedID, 1)
	assertChildRowCount(t, core.DB(), "share_correlation", staleInterruptedID, 1)

	interrupted, err := core.GetTestRun(ctx, staleInterruptedID)
	if err != nil {
		t.Fatalf("GetTestRun %s: %v (interrupted run must remain)", staleInterruptedID, err)
	}

	if interrupted.TerminalReason == nil || *interrupted.TerminalReason != ReasonReverseShareTimeout {
		t.Fatalf(
			"%s terminal_reason = %v, want %q",
			staleInterruptedID,
			interrupted.TerminalReason,
			ReasonReverseShareTimeout,
		)
	}

	tombstoned, err := core.GetTestRun(ctx, tombstonedID)
	if err != nil {
		t.Fatalf("GetTestRun %s: %v (already-tombstoned permanent row must remain)", tombstonedID, err)
	}

	if tombstoned.HarvestedAt == nil || *tombstoned.HarvestedAt != knownHarvested {
		t.Fatalf("%s harvested_at = %v, want unchanged %d", tombstonedID, tombstoned.HarvestedAt, knownHarvested)
	}

	if tombstoned.HarvestReason == nil || *tombstoned.HarvestReason != knownReason {
		t.Fatalf("%s harvest_reason = %v, want unchanged %q", tombstonedID, tombstoned.HarvestReason, knownReason)
	}
}

func TestStartupMaintenance_PrunesTerminalRetention(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.SetSessionConfig(SessionConfig{
		InFlightPassiveLimit:  10,
		CreatedTTLSeconds:     3600,
		TerminalRetentionDays: 30,
	})

	ctx := t.Context()
	now := time.Now().Unix()
	pass := GradePass

	if err := core.InsertStatsRaw(ctx, &StatsRaw{
		K:              "k-startup-old",
		HostHash:       "startup-host",
		SessionKind:    SessionKindPassiveOnly,
		Platform:       "Old",
		GradeDiscovery: new(pass),
		CreatedAt:      now - int64(60*24*3600),
	}); err != nil {
		t.Fatalf("insert stale stats_raw: %v", err)
	}

	if err := core.InsertStatsRaw(ctx, &StatsRaw{
		K:              "k-startup-new",
		HostHash:       "startup-host",
		SessionKind:    SessionKindPassiveOnly,
		Platform:       "New",
		GradeDiscovery: new(pass),
		CreatedAt:      now - 3600,
	}); err != nil {
		t.Fatalf("insert recent stats_raw: %v", err)
	}

	if err := core.startupMaintenance(ctx); err != nil {
		t.Fatalf("startupMaintenance: %v", err)
	}

	var remaining []StatsRaw
	if err := core.DB().WithContext(ctx).Find(&remaining).Error; err != nil {
		t.Fatalf("load stats_raw after startup maintenance: %v", err)
	}

	if len(remaining) != 1 || remaining[0].K != "k-startup-new" {
		t.Fatalf("startup prune remaining = %+v, want only k-startup-new", remaining)
	}
}
