// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func retentionSweepSessionConfig(retentionDays int) SessionConfig {
	return SessionConfig{
		InFlightPassiveLimit:      10,
		CreatedTTLSeconds:         3600,
		PassiveRunningTTLSeconds:  3600,
		PassiveCompleteTTLSeconds: 3600,
		TerminalRetentionDays:     retentionDays,
	}
}

func TestSweepRetentionAndPrune_HealsStatsBeforePermanentTombstone(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.SetStatsHostHasher(testStatsHostHasher(t))
	core.SetSessionConfig(retentionSweepSessionConfig(30))

	ctx := t.Context()
	now := time.Now().Unix()
	// finished_at stays inside the stats retention window so the healed
	// stats_raw row is not immediately aged out. expires_at is already
	// past so the permanent tombstone still runs in the same pass.
	finished := now - 3600
	expires := now - 60
	id := "run-sweep-heal-before-wipe"

	seedExpiredPermanentRun(t, core.DB(), ctx, id, finished, expires)
	mustExec(t, core.DB(), "UPDATE test_run SET opt_in_stats = 1 WHERE test_run_id = '"+id+"'")
	seedEvidenceRow(
		t,
		core,
		id,
		evidenceLegPassive,
		SpecificationAreaDiscovery,
		"request",
		"probed",
		GradePass,
		true,
	)

	if err := core.sweepRetentionAndPrune(ctx); err != nil {
		t.Fatalf("sweepRetentionAndPrune: %v", err)
	}

	requireStatsWrittenAt(t, core, id, true)

	if count := countStatsRaw(t, core); count != 1 {
		t.Fatalf("stats_raw count = %d, want 1 (heal must land before PII wipe)", count)
	}

	var raw StatsRaw
	if err := core.DB().WithContext(ctx).First(&raw).Error; err != nil {
		t.Fatalf("load healed stats_raw: %v", err)
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

	got, err := core.GetTestRun(ctx, id)
	if err != nil {
		t.Fatalf("GetTestRun: %v (parent must survive as a tombstone)", err)
	}

	assertHardExpiryTombstone(t, got)
	assertChildRowCount(t, core.DB(), "evidence_row", id, 0)
}

func TestSweepRetentionAndPrune_PrunesAgedNonPermanentAndKeepsInterrupted(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.SetSessionConfig(retentionSweepSessionConfig(30))

	ctx := t.Context()
	now := time.Now().Unix()
	staleFinished := now - int64(60*24*3600)
	recentFinished := now - 3600
	timeoutReason := ReasonReverseShareTimeout
	staleReason := "probe_finished"
	passID := "run-sweep-aged-pass"
	failID := "run-sweep-aged-fail"
	interruptedID := "run-sweep-aged-interrupted"
	recentID := "run-sweep-recent-pass"

	seedTerminalRun(t, core.DB(), ctx, passID, staleFinished, staleReason)
	seedTerminalRun(t, core.DB(), ctx, failID, staleFinished, staleReason)
	mustExec(t, core.DB(), "UPDATE test_run SET state = '"+StateTerminalFail+"' WHERE test_run_id = '"+failID+"'")

	if err := core.DB().WithContext(ctx).Create(&TestRun{
		TestRunID:      interruptedID,
		State:          StateInterrupted,
		TargetOrigin:   "https://target.example",
		TargetHost:     "target.example",
		DiscoveryURL:   "https://target.example/.well-known/ocm",
		JwksURI:        "https://target.example/jwks.json",
		ManifestSchema: "ocm-validator-manifest/v1",
		TerminalReason: &timeoutReason,
		FinishedAt:     &staleFinished,
		CreatedAt:      staleFinished,
		UpdatedAt:      staleFinished,
	}).Error; err != nil {
		t.Fatalf("seed interrupted run: %v", err)
	}

	seedRunChildSet(t, core.DB(), interruptedID)
	seedTerminalRun(t, core.DB(), ctx, recentID, recentFinished, staleReason)

	if err := core.sweepRetentionAndPrune(ctx); err != nil {
		t.Fatalf("sweepRetentionAndPrune: %v", err)
	}

	assertRunHardDeleted(t, core, core.DB(), passID)
	assertRunHardDeleted(t, core, core.DB(), failID)
	assertNoTombstone(t, core, interruptedID, StateInterrupted)
	assertNoTombstone(t, core, recentID, StateTerminalPass)
	assertChildRowCount(t, core.DB(), "report_exchange", interruptedID, 1)
	assertChildRowCount(t, core.DB(), "evidence_row", interruptedID, 1)
	assertChildRowCount(t, core.DB(), "dispatch_reservation", interruptedID, 1)
	assertChildRowCount(t, core.DB(), "share_correlation", interruptedID, 1)

	interrupted, err := core.GetTestRun(ctx, interruptedID)
	if err != nil {
		t.Fatalf("GetTestRun %s: %v", interruptedID, err)
	}

	if interrupted.TerminalReason == nil || *interrupted.TerminalReason != ReasonReverseShareTimeout {
		t.Fatalf(
			"%s terminal_reason = %v, want %q",
			interruptedID,
			interrupted.TerminalReason,
			ReasonReverseShareTimeout,
		)
	}
}

func TestSweepRetentionAndPrune_PrunesAgedStatsRawAndKeepsRecent(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.SetSessionConfig(retentionSweepSessionConfig(30))

	ctx := t.Context()
	now := time.Now().Unix()
	staleFinished := now - int64(60*24*3600)
	recentFinished := now - 3600
	agedID := "run-sweep-stats-aged"
	recentID := "run-sweep-stats-recent"
	agedK := "k-sweep-stats-aged"
	recentK := "k-sweep-stats-recent"
	pass := GradePass

	// stats_raw has no test_run_id. Pair each snapshot with a matching
	// session so the enabled sweep runs both terminal prune and PruneStats.
	seedTerminalRun(t, core.DB(), ctx, agedID, staleFinished, "probe_finished")
	seedTerminalRun(t, core.DB(), ctx, recentID, recentFinished, "probe_finished")

	if err := core.InsertStatsRaw(ctx, &StatsRaw{
		K:              agedK,
		HostHash:       "hash-sweep-aged",
		SessionKind:    SessionKindPassiveOnly,
		Platform:       "Aged",
		GradeDiscovery: &pass,
		CreatedAt:      staleFinished,
	}); err != nil {
		t.Fatalf("insert aged stats_raw: %v", err)
	}

	if err := core.InsertStatsRaw(ctx, &StatsRaw{
		K:              recentK,
		HostHash:       "hash-sweep-recent",
		SessionKind:    SessionKindPassiveOnly,
		Platform:       "Recent",
		GradeDiscovery: &pass,
		CreatedAt:      recentFinished,
	}); err != nil {
		t.Fatalf("insert recent stats_raw: %v", err)
	}

	if err := core.sweepRetentionAndPrune(ctx); err != nil {
		t.Fatalf("sweepRetentionAndPrune: %v", err)
	}

	assertRunHardDeleted(t, core, core.DB(), agedID)
	assertNoTombstone(t, core, recentID, StateTerminalPass)

	var remaining []StatsRaw
	if err := core.DB().WithContext(ctx).Find(&remaining).Error; err != nil {
		t.Fatalf("load remaining stats_raw: %v", err)
	}

	if len(remaining) != 1 || remaining[0].K != recentK {
		t.Fatalf("remaining stats_raw = %+v, want only %s", remaining, recentK)
	}

	if core.DB().Migrator().HasTable(tableStatsAggregate) {
		t.Fatal("stats_aggregate must stay absent (PruneStats deletes stats_raw only)")
	}
}

func TestSweepRetentionAndPrune_SkipsTerminalPruneWhenRetentionDaysNonPositive(t *testing.T) {
	t.Parallel()

	for _, days := range []int{0, -1} {
		t.Run(fmt.Sprintf("days=%d", days), func(t *testing.T) {
			t.Parallel()

			core := openTestCore(t)
			core.SetSessionConfig(retentionSweepSessionConfig(days))

			ctx := t.Context()
			now := time.Now().Unix()
			staleFinished := now - int64(60*24*3600)
			expires := now - 60
			pass := GradePass
			agedID := "run-sweep-noprune-aged"
			permanentID := "run-sweep-noprune-permanent"

			seedTerminalRun(t, core.DB(), ctx, agedID, staleFinished, "probe_finished")
			seedExpiredPermanentRun(t, core.DB(), ctx, permanentID, staleFinished, expires)

			if err := core.InsertStatsRaw(ctx, &StatsRaw{
				K:              fmt.Sprintf("k-noprune-%d", days),
				HostHash:       "hash-noprune",
				SessionKind:    SessionKindPassiveOnly,
				Platform:       "Keep",
				GradeDiscovery: &pass,
				CreatedAt:      staleFinished,
			}); err != nil {
				t.Fatalf("insert stale stats_raw: %v", err)
			}

			if err := core.sweepRetentionAndPrune(ctx); err != nil {
				t.Fatalf("sweepRetentionAndPrune: %v", err)
			}

			assertNoTombstone(t, core, agedID, StateTerminalPass)

			if count := countStatsRaw(t, core); count != 1 {
				t.Fatalf("stats_raw count = %d, want 1 (non-positive retention must not prune stats)", count)
			}

			permanent, err := core.GetTestRun(ctx, permanentID)
			if err != nil {
				t.Fatalf("GetTestRun %s: %v", permanentID, err)
			}

			assertHardExpiryTombstone(t, permanent)
		})
	}
}

func TestStartRetentionSweep_PrunesAgedNonPermanentWithoutRestart(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.SetSessionConfig(retentionSweepSessionConfig(30))

	ctx, cancel := context.WithCancel(t.Context())
	now := time.Now().Unix()
	staleFinished := now - int64(60*24*3600)
	runID := "run-retention-ticker-aged"

	// Seeded after the store is already live, so only a periodic pass can
	// reap it. Startup maintenance never runs on this handle.
	seedTerminalRun(t, core.DB(), ctx, runID, staleFinished, "probe_finished")

	done := make(chan struct{})

	go func() {
		defer close(done)

		core.startRetentionSweep(ctx, 10*time.Millisecond)
	}()

	t.Cleanup(func() {
		cancel()
		<-done
	})

	deadline := time.Now().Add(10 * time.Second)

	for {
		_, err := core.GetTestRun(ctx, runID)
		if errors.Is(err, ErrSessionNotFound) {
			break
		}

		if err != nil {
			t.Fatalf("GetTestRun: %v", err)
		}

		if time.Now().After(deadline) {
			t.Fatal("aged non-permanent pass still present, want the periodic sweep to prune it")
		}

		time.Sleep(20 * time.Millisecond)
	}

	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("retention sweep goroutine did not return after cancel")
	}
}
