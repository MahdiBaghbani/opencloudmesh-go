// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"testing"
	"time"
)

// seedTerminalStatsGap seeds an opted-in terminal_pass row whose stats write
// never landed: the primary heal target.
func seedTerminalStatsGap(t *testing.T, core *Core, runID, targetOrigin string) {
	t.Helper()

	finished := time.Now().Unix()

	if err := core.DB().WithContext(t.Context()).Create(&TestRun{
		TestRunID:    runID,
		IsActive:     false,
		State:        StateTerminalPass,
		SessionKind:  SessionKindActiveFull,
		TargetOrigin: targetOrigin,
		TargetHost:   "peer.example",
		FinishedAt:   &finished,
		OptInStats:   true,
		CreatedAt:    finished,
		UpdatedAt:    finished,
	}).Error; err != nil {
		t.Fatalf("seed terminal stats gap %s: %v", runID, err)
	}
}

func requireStatsWrittenAt(t *testing.T, core *Core, runID string, wantStamped bool) {
	t.Helper()

	got, err := core.GetTestRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetTestRun %s: %v", runID, err)
	}

	if wantStamped && got.StatsWrittenAt == nil {
		t.Fatalf("%s: stats_written_at = nil, want healed", runID)
	}

	if !wantStamped && got.StatsWrittenAt != nil {
		t.Fatalf("%s: stats_written_at = %v, want nil (the row must stay unhealed)", runID, got.StatsWrittenAt)
	}
}

func TestHealMissingTerminalStats_SkipsUnflippableInterruptedRuns(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.SetStatsHostHasher(testStatsHostHasher(t))
	ctx := t.Context()

	// Eligible rows: a terminal_pass gap and the one flippable interruption.
	seedTerminalStatsGap(t, core, "run-heal-eligible-pass", "https://peer.example")
	seedInterruptedRun(t, core, "run-heal-eligible-timeout", ReasonReverseShareTimeout, true)

	// Unflippable interrupted rows: opted in with missing stats, yet never
	// eligible for the heal.
	seedInterruptedRun(t, core, "run-heal-skip-stall", "stall_inactivity_expired", true)
	seedInterruptedRun(t, core, "run-heal-skip-startup", "startup_unrecoverable_active", true)
	seedInterruptedRun(t, core, "run-heal-skip-invite", "reverse_invite_timeout", true)

	// Grade-affecting evidence recorded for an unflippable row (a late share
	// the flip refused) must never be graded through the heal.
	now := time.Now().Unix()
	if err := core.DB().WithContext(ctx).Create(&EvidenceRow{
		TestRunID:    "run-heal-skip-stall",
		Area:         "sharing",
		Step:         "reverse_share",
		ReasonCode:   "reverse_share_received",
		Severity:     "info",
		AffectsGrade: true,
		CreatedAt:    now,
	}).Error; err != nil {
		t.Fatalf("seed evidence for unflippable run: %v", err)
	}

	if err := core.HealMissingTerminalStats(ctx); err != nil {
		t.Fatalf("HealMissingTerminalStats: %v", err)
	}

	requireStatsWrittenAt(t, core, "run-heal-eligible-pass", true)
	requireStatsWrittenAt(t, core, "run-heal-eligible-timeout", true)

	for _, runID := range []string{"run-heal-skip-stall", "run-heal-skip-startup", "run-heal-skip-invite"} {
		requireStatsWrittenAt(t, core, runID, false)
	}

	if count := countStatsRaw(t, core); count != 2 {
		t.Fatalf("stats_raw count = %d, want 2 (only eligible rows healed)", count)
	}
}

func TestHealMissingTerminalStats_ContinuesAfterRowError(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.SetStatsHostHasher(testStatsHostHasher(t))
	ctx := t.Context()

	// Seeded first but always fails its stats write: the empty target origin
	// breaks host hashing. Later eligible rows must still heal, and the pass
	// must not surface the row's failure as a global error.
	seedTerminalStatsGap(t, core, "run-heal-row-error", "")
	seedTerminalStatsGap(t, core, "run-heal-row-ok-1", "https://peer.example")
	seedTerminalStatsGap(t, core, "run-heal-row-ok-2", "https://peer.example")

	if err := core.HealMissingTerminalStats(ctx); err != nil {
		t.Fatalf("HealMissingTerminalStats: %v, want per-row errors tolerated", err)
	}

	requireStatsWrittenAt(t, core, "run-heal-row-ok-1", true)
	requireStatsWrittenAt(t, core, "run-heal-row-ok-2", true)
	requireStatsWrittenAt(t, core, "run-heal-row-error", false)

	if count := countStatsRaw(t, core); count != 2 {
		t.Fatalf("stats_raw count = %d, want 2 (the failed row must not starve later rows)", count)
	}
}
