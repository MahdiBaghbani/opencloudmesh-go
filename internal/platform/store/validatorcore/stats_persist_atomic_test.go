// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"strings"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/statistics"
)

func assertHostRawTotals(t *testing.T, core *Core, hostHash string, total, healthy int64) {
	t.Helper()

	var raws []StatsRaw
	if err := core.DB().WithContext(t.Context()).Find(&raws, "host_hash = ?", hostHash).Error; err != nil {
		t.Fatalf("load stats_raw: %v", err)
	}

	if int64(len(raws)) != total {
		t.Fatalf("stats_raw count = %d, want %d", len(raws), total)
	}

	var gotHealthy int64

	for _, raw := range raws {
		if DeriveHealthy(raw) {
			gotHealthy++
		}
	}

	if gotHealthy != healthy {
		t.Fatalf("healthy stats_raw count = %d, want %d", gotHealthy, healthy)
	}
}

func TestPersistTerminalStats_WrongRunDoesNotReplaceRaw(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.SetStatsHostHasher(testStatsHostHasher(t))
	ctx := t.Context()
	now := time.Now().Unix()
	pass := GradePass
	fail := GradeFail

	// Two terminal runs against the same target share host_hash but must get
	// distinct dedup keys; a key derived from anything but the run id would
	// let the second run replace the first.
	seedTerminalStatsRun(t, core, "run-wrong-run-a", now-10)
	seedTerminalStatsRun(t, core, "run-wrong-run-b", now)

	seedEvidenceRow(t, core, "run-wrong-run-a", evidenceLegPassive, SpecificationAreaDiscovery, "fetch", "discovery_ok", pass, true)
	seedEvidenceRow(t, core, "run-wrong-run-b", evidenceLegPassive, SpecificationAreaDiscovery, "fetch", "discovery_missing", fail, true)

	if err := core.persistTerminalStats(ctx, "run-wrong-run-a"); err != nil {
		t.Fatalf("persist run a: %v", err)
	}

	if err := core.persistTerminalStats(ctx, "run-wrong-run-b"); err != nil {
		t.Fatalf("persist run b: %v", err)
	}

	var raws []StatsRaw
	if err := core.DB().WithContext(ctx).Order("created_at ASC").Find(&raws).Error; err != nil {
		t.Fatalf("load stats_raw: %v", err)
	}

	if len(raws) != 2 {
		t.Fatalf("stats_raw count = %d, want 2 distinct runs", len(raws))
	}

	if raws[0].K == raws[1].K {
		t.Fatal("dedup keys must differ per test run")
	}

	assertHostRawTotals(t, core, raws[0].HostHash, 2, 1)

	if DeriveHealthy(raws[1]) {
		t.Fatal("expected later fail-grade run to be unhealthy")
	}

	// A retry of the first run is a no-op: no third row, no counter drift.
	if err := core.persistTerminalStats(ctx, "run-wrong-run-a"); err != nil {
		t.Fatalf("re-persist run a: %v", err)
	}

	var rawCount int64
	if err := core.DB().WithContext(ctx).Model(&StatsRaw{}).Count(&rawCount).Error; err != nil {
		t.Fatalf("count stats_raw: %v", err)
	}

	if rawCount != 2 {
		t.Fatalf("stats_raw count = %d after retry, want 2", rawCount)
	}

	assertHostRawTotals(t, core, raws[0].HostHash, 2, 1)
}

func TestPersistTerminalStats_FillsMissingGradesFromEvidence(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.SetStatsHostHasher(testStatsHostHasher(t))
	ctx := t.Context()
	now := time.Now().Unix()
	runID := "run-stats-evidence-fill"

	seedTerminalStatsRun(t, core, runID, now)
	seedEvidenceRow(t, core, runID, evidenceLegPassive, "discovery", "fetch", "discovery_document_missing", "fail", true)
	seedEvidenceRow(t, core, runID, evidenceLegPassive, "tls", "handshake", "cert_expiry_near", "important", true)
	seedEvidenceRow(t, core, runID, evidenceLegPassive, "jwks", "fetch", "jwks_served", "info", true)
	seedEvidenceRow(t, core, runID, evidenceLegForward, "sharing", "create", "share_note", "fail", false)

	if err := core.persistTerminalStats(ctx, runID); err != nil {
		t.Fatalf("persist: %v", err)
	}

	var raw StatsRaw
	if err := core.DB().WithContext(ctx).First(&raw).Error; err != nil {
		t.Fatalf("load stats_raw: %v", err)
	}

	if raw.GradeDiscovery == nil || *raw.GradeDiscovery != GradeFail {
		t.Fatalf("grade_discovery = %v, want fail from evidence", raw.GradeDiscovery)
	}

	if raw.GradeTLS == nil || *raw.GradeTLS != GradeWarn {
		t.Fatalf("grade_tls = %v, want warn from evidence", raw.GradeTLS)
	}

	if raw.GradeJWKS == nil || *raw.GradeJWKS != GradePass {
		t.Fatalf("grade_jwks = %v, want pass from grade-affecting evidence", raw.GradeJWKS)
	}

	if raw.GradeSharing != nil {
		t.Fatalf("grade_sharing = %v, want nil for non-grade-affecting evidence", raw.GradeSharing)
	}

	if raw.GradeToken != nil {
		t.Fatalf("grade_token = %v, want nil without evidence", raw.GradeToken)
	}
}

func TestPersistTerminalStats_EvidenceGradeDeterminesDiscovery(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.SetStatsHostHasher(testStatsHostHasher(t))
	ctx := t.Context()
	now := time.Now().Unix()
	runID := "run-stats-evidence-discovery"

	seedTerminalStatsRun(t, core, runID, now)
	seedEvidenceRow(t, core, runID, evidenceLegPassive, SpecificationAreaDiscovery, "fetch", "discovery_document_missing", GradeFail, true)

	if err := core.persistTerminalStats(ctx, runID); err != nil {
		t.Fatalf("persist: %v", err)
	}

	var raw StatsRaw
	if err := core.DB().WithContext(ctx).First(&raw).Error; err != nil {
		t.Fatalf("load stats_raw: %v", err)
	}

	if raw.GradeDiscovery == nil || *raw.GradeDiscovery != GradeFail {
		t.Fatalf("grade_discovery = %v, want fail from evidence", raw.GradeDiscovery)
	}
}

func TestPersistTerminalStats_ConcurrentSameRunWritesOnce(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.SetStatsHostHasher(testStatsHostHasher(t))
	ctx := t.Context()
	now := time.Now().Unix()
	runID := "run-stats-concurrent-same-run"

	seedTerminalStatsRun(t, core, runID, now)

	// Two concurrent persists of one run share host_hash and dedup key.
	// SQLite serializes writers: one transaction commits, and the other
	// either no-ops at the write-once guard or fails fast with SQLITE_BUSY
	// (no busy timeout is configured on the test handle). Both outcomes are
	// safe; what must hold is exactly-once stats state with no double-count.
	const writers = 2

	start := make(chan struct{})
	errs := make(chan error, writers)

	for range writers {
		go func() {
			<-start

			errs <- core.persistTerminalStats(ctx, runID)
		}()
	}

	close(start)

	succeeded := 0

	for range writers {
		err := <-errs
		if err == nil {
			succeeded++

			continue
		}

		if !strings.Contains(err.Error(), "SQLITE_BUSY") {
			t.Fatalf("concurrent persist error = %v, want nil or SQLITE_BUSY serialization", err)
		}
	}

	if succeeded == 0 {
		t.Fatal("at least one concurrent persist must succeed")
	}

	var rawCount int64
	if err := core.DB().WithContext(ctx).Model(&StatsRaw{}).Count(&rawCount).Error; err != nil {
		t.Fatalf("count stats_raw: %v", err)
	}

	if rawCount != 1 {
		t.Fatalf("stats_raw count = %d, want exactly 1 after concurrent same-run persists", rawCount)
	}

	var raw StatsRaw
	if err := core.DB().WithContext(ctx).First(&raw).Error; err != nil {
		t.Fatalf("load stats_raw: %v", err)
	}

	assertHostRawTotals(t, core, raw.HostHash, 1, 0)

	var row TestRun
	if err := core.DB().WithContext(ctx).First(&row, "test_run_id = ?", runID).Error; err != nil {
		t.Fatalf("reload test run: %v", err)
	}

	if row.StatsWrittenAt == nil {
		t.Fatal("stats_written_at = NULL, want stamped by the winning persist")
	}
}

func TestInsertStatsRawOrIgnore_ConflictIsNoOp(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()

	first := &StatsRaw{
		K:           "k-insert-conflict",
		HostHash:    "hash-insert-conflict",
		SessionKind: SessionKindPassiveOnly,
		CreatedAt:   100,
	}

	inserted, err := insertStatsRawOrIgnore(core.DB().WithContext(ctx), first)
	if err != nil {
		t.Fatalf("first insert: %v", err)
	}

	if !inserted {
		t.Fatal("first insert reported not inserted")
	}

	duplicate := &StatsRaw{
		K:           "k-insert-conflict",
		HostHash:    "hash-insert-conflict",
		SessionKind: SessionKindPassiveOnly,
		CreatedAt:   200,
	}

	inserted, err = insertStatsRawOrIgnore(core.DB().WithContext(ctx), duplicate)
	if err != nil {
		t.Fatalf("conflict insert must not error, got: %v", err)
	}

	if inserted {
		t.Fatal("conflict insert reported inserted, want ON CONFLICT(k) DO NOTHING no-op")
	}

	var count int64
	if err := core.DB().WithContext(ctx).Model(&StatsRaw{}).Count(&count).Error; err != nil {
		t.Fatalf("count stats_raw: %v", err)
	}

	if count != 1 {
		t.Fatalf("stats_raw count = %d, want 1 after conflict no-op", count)
	}

	var surviving StatsRaw
	if err := core.DB().WithContext(ctx).First(&surviving).Error; err != nil {
		t.Fatalf("load stats_raw: %v", err)
	}

	if surviving.ID != first.ID || surviving.CreatedAt != 100 {
		t.Fatalf("surviving row = (id %d, created_at %d), want original (id %d, created_at 100)",
			surviving.ID, surviving.CreatedAt, first.ID)
	}
}

func TestPersistTerminalStats_WorstEvidenceGradeWinsPerArea(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.SetStatsHostHasher(testStatsHostHasher(t))
	ctx := t.Context()
	now := time.Now().Unix()
	runID := "run-stats-evidence-worst"

	seedTerminalStatsRun(t, core, runID, now)

	// Multiple grade-affecting entries in one area merge to the worst grade.
	// Non-monotonic insertion (fail first, pass last) defeats last-write-wins.
	seedEvidenceRow(t, core, runID, evidenceLegPassive, "tls", "chain", "cert_chain_invalid", "fail", true)
	seedEvidenceRow(t, core, runID, evidenceLegPassive, "tls", "cert-validity", "cert_expiry_near", "warning", true)
	seedEvidenceRow(t, core, runID, evidenceLegPassive, "tls", "handshake", "tls_served", "info", true)

	seedEvidenceRow(t, core, runID, evidenceLegPassive, "discovery", "fetch", "discovery_document_missing", "fail", true)

	if err := core.persistTerminalStats(ctx, runID); err != nil {
		t.Fatalf("persist: %v", err)
	}

	var raw StatsRaw
	if err := core.DB().WithContext(ctx).First(&raw).Error; err != nil {
		t.Fatalf("load stats_raw: %v", err)
	}

	if raw.GradeTLS == nil || *raw.GradeTLS != GradeFail {
		t.Fatalf("grade_tls = %v, want fail (worst grade, independent of evidence insertion order)", raw.GradeTLS)
	}

	if raw.GradeDiscovery == nil || *raw.GradeDiscovery != GradeFail {
		t.Fatalf("grade_discovery = %v, want fail from evidence", raw.GradeDiscovery)
	}
}

func TestPersistTerminalStats_DedupKeyMatchesStatsSessionHash(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.SetStatsHostHasher(testStatsHostHasher(t))
	ctx := t.Context()
	now := time.Now().Unix()
	runID := "run-stats-dedup-key-derivation"

	seedTerminalStatsRun(t, core, runID, now)

	if err := core.persistTerminalStats(ctx, runID); err != nil {
		t.Fatalf("persist: %v", err)
	}

	var raw StatsRaw
	if err := core.DB().WithContext(ctx).First(&raw).Error; err != nil {
		t.Fatalf("load stats_raw: %v", err)
	}

	// The stored dedup key must be the real keyed-BLAKE3 output for the
	// stats-session|<test_run_id> context under the test salt, computed by
	// the shared statistics hasher rather than a hardcoded digest.
	salt := make([]byte, statistics.RedactionSaltSize)
	for i := range salt {
		salt[i] = byte(i + 1)
	}

	want, err := statistics.HashStatsK(salt, runID)
	if err != nil {
		t.Fatalf("HashStatsK: %v", err)
	}

	if raw.K != want {
		t.Fatalf("k = %q, want keyed-BLAKE3 stats-session digest %q", raw.K, want)
	}
}
