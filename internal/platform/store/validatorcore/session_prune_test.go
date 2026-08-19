// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"context"
	"testing"
	"time"

	"gorm.io/gorm"

	store "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
)

func TestPruneTerminalSessions_TombstonesRunAndHarvestsChildren(t *testing.T) {
	t.Parallel()

	// sqlitecore enables PRAGMA foreign_keys on every connection, so this
	// store enforces the ON DELETE RESTRICT contract the way production does.
	sqlCore := openPeerStore(t)

	core, attachErr := Attach(sqlCore.DB(), DefaultSessionConfig())
	if attachErr != nil {
		t.Fatalf("Attach: %v", attachErr)
	}

	db := core.DB()
	ctx := t.Context()

	var fkEnforced int

	if scanErr := db.Raw("PRAGMA foreign_keys").Scan(&fkEnforced).Error; scanErr != nil {
		t.Fatalf("read foreign_keys pragma: %v", scanErr)
	}

	if fkEnforced != 1 {
		t.Fatalf("foreign_keys = %d, want 1 (restrict proof requires enforcement)", fkEnforced)
	}

	now := time.Now().Unix()
	staleFinished := now - int64(60*24*3600)
	recentFinished := now - 3600
	staleReason := "probe_finished"

	seedTerminalRun(t, db, ctx, "run-prune-stale", staleFinished, staleReason)
	seedTerminalRun(t, db, ctx, "run-prune-recent", recentFinished, staleReason)

	// An old non-terminal run must never be pruned or tombstoned.
	nonTerminal := &TestRun{
		TestRunID:      "run-prune-nonterminal",
		State:          StatePassiveRunning,
		TargetOrigin:   "https://target.example",
		TargetHost:     "target.example",
		DiscoveryURL:   "https://target.example/.well-known/ocm",
		JwksURI:        "https://target.example/jwks.json",
		ManifestSchema: "ocm-validator-manifest/v1",
		SessionKind:    SessionKindPassiveOnly,
		CreatedAt:      staleFinished,
		UpdatedAt:      staleFinished,
	}

	if createErr := db.WithContext(ctx).Create(nonTerminal).Error; createErr != nil {
		t.Fatalf("seed non-terminal run: %v", createErr)
	}

	seedPruneChildRows(t, db)

	// Peer persistence shares the database and must never be touched.
	peer := store.OutgoingShare{
		ShareID:    "share-prune",
		ProviderID: "provider-prune",
		WebDAVID:   "webdav-prune",
		CreatedAt:  1,
	}

	if peerErr := db.WithContext(ctx).Create(&peer).Error; peerErr != nil {
		t.Fatalf("seed peer row: %v", peerErr)
	}

	if pruneErr := core.PruneTerminalSessions(ctx, 30); pruneErr != nil {
		t.Fatalf("PruneTerminalSessions with child rows: %v", pruneErr)
	}

	// Child artifacts of the pruned run are harvested; the parent remains.
	assertChildRowCount(t, db, "report_exchange", "run-prune-stale", 0)
	assertChildRowCount(t, db, "evidence_row", "run-prune-stale", 0)
	assertChildRowCount(t, db, "dispatch_reservation", "run-prune-stale", 0)
	assertChildRowCount(t, db, "share_correlation", "run-prune-stale", 0)

	assertTombstone(t, core, "run-prune-stale", staleReason, staleFinished)

	// The too-recent terminal run keeps its child and stays untombstoned.
	assertNoTombstone(t, core, "run-prune-recent", StateTerminalPass)
	assertChildRowCount(t, db, "report_exchange", "run-prune-recent", 1)

	// The old non-terminal run is outside the prune selection entirely.
	assertNoTombstone(t, core, "run-prune-nonterminal", StatePassiveRunning)

	var peerCount int64

	mustQueryCount(t, db, "SELECT COUNT(*) FROM outgoing_shares WHERE share_id = 'share-prune'", &peerCount)

	if peerCount != 1 {
		t.Fatalf("peer outgoing_shares rows = %d, want 1 (peer tables untouched)", peerCount)
	}
}

func TestPruneTerminalSessions_SparesInterruptedRun(t *testing.T) {
	t.Parallel()

	sqlCore := openPeerStore(t)

	core, attachErr := Attach(sqlCore.DB(), DefaultSessionConfig())
	if attachErr != nil {
		t.Fatalf("Attach: %v", attachErr)
	}

	db := core.DB()
	ctx := t.Context()

	now := time.Now().Unix()
	staleFinished := now - int64(60*24*3600)

	// An aged interrupted run is outside the prune selection: only
	// terminal_pass and terminal_fail rows are tombstoned, even when
	// finished_at is older than the retention window.
	interrupted := &TestRun{
		TestRunID:      "run-prune-interrupted",
		State:          StateInterrupted,
		TargetOrigin:   "https://target.example",
		TargetHost:     "target.example",
		DiscoveryURL:   "https://target.example/.well-known/ocm",
		JwksURI:        "https://target.example/jwks.json",
		ManifestSchema: "ocm-validator-manifest/v1",
		SessionKind:    SessionKindPassiveOnly,
		FinishedAt:     &staleFinished,
		CreatedAt:      staleFinished,
		UpdatedAt:      staleFinished,
	}

	if createErr := db.WithContext(ctx).Create(interrupted).Error; createErr != nil {
		t.Fatalf("seed interrupted run: %v", createErr)
	}

	seedRunChildSet(t, db, "run-prune-interrupted")

	if pruneErr := core.PruneTerminalSessions(ctx, 30); pruneErr != nil {
		t.Fatalf("PruneTerminalSessions: %v", pruneErr)
	}

	got, err := core.GetTestRun(ctx, "run-prune-interrupted")
	if err != nil {
		t.Fatalf("GetTestRun run-prune-interrupted: %v (interrupted row must survive)", err)
	}

	if got.State != StateInterrupted {
		t.Fatalf("state = %q, want unchanged %q", got.State, StateInterrupted)
	}

	if got.IsActive {
		t.Fatal("is_active = 1, want unchanged 0")
	}

	if got.HarvestedAt != nil || got.HarvestReason != nil {
		t.Fatalf("tombstone = (%v, %v), want both NULL", got.HarvestedAt, got.HarvestReason)
	}

	assertChildRowCount(t, db, "report_exchange", "run-prune-interrupted", 1)
	assertChildRowCount(t, db, "evidence_row", "run-prune-interrupted", 1)
	assertChildRowCount(t, db, "dispatch_reservation", "run-prune-interrupted", 1)
	assertChildRowCount(t, db, "share_correlation", "run-prune-interrupted", 1)
}

func TestPruneTerminalSessions_SkipsAlreadyHarvestedRun(t *testing.T) {
	t.Parallel()

	sqlCore := openPeerStore(t)

	core, attachErr := Attach(sqlCore.DB(), DefaultSessionConfig())
	if attachErr != nil {
		t.Fatalf("Attach: %v", attachErr)
	}

	db := core.DB()
	ctx := t.Context()

	now := time.Now().Unix()
	staleFinished := now - int64(60*24*3600)
	knownHarvested := now - int64(10*24*3600)
	knownReason := harvestReasonRetentionExpired

	// A row tombstoned by an earlier prune run keeps its original
	// harvested_at and harvest_reason when prune runs again.
	harvested := &TestRun{
		TestRunID:      "run-prune-harvested",
		State:          StateTerminalPass,
		TargetOrigin:   "https://target.example",
		TargetHost:     "target.example",
		DiscoveryURL:   "https://target.example/.well-known/ocm",
		JwksURI:        "https://target.example/jwks.json",
		ManifestSchema: "ocm-validator-manifest/v1",
		SessionKind:    SessionKindPassiveOnly,
		FinishedAt:     &staleFinished,
		HarvestedAt:    &knownHarvested,
		HarvestReason:  &knownReason,
		CreatedAt:      staleFinished,
		UpdatedAt:      staleFinished,
	}

	if createErr := db.WithContext(ctx).Create(harvested).Error; createErr != nil {
		t.Fatalf("seed harvested run: %v", createErr)
	}

	if pruneErr := core.PruneTerminalSessions(ctx, 30); pruneErr != nil {
		t.Fatalf("PruneTerminalSessions: %v", pruneErr)
	}

	got, err := core.GetTestRun(ctx, "run-prune-harvested")
	if err != nil {
		t.Fatalf("GetTestRun run-prune-harvested: %v", err)
	}

	if got.HarvestedAt == nil || *got.HarvestedAt != knownHarvested {
		t.Fatalf("harvested_at = %v, want unchanged %d", got.HarvestedAt, knownHarvested)
	}

	if got.HarvestReason == nil || *got.HarvestReason != knownReason {
		t.Fatalf("harvest_reason = %v, want unchanged %q", got.HarvestReason, knownReason)
	}
}

func seedTerminalRun(t *testing.T, db *gorm.DB, ctx context.Context, id string, finished int64, reason string) {
	t.Helper()

	row := &TestRun{
		TestRunID:      id,
		State:          StateTerminalPass,
		TargetOrigin:   "https://target.example",
		TargetHost:     "target.example",
		DiscoveryURL:   "https://target.example/.well-known/ocm",
		JwksURI:        "https://target.example/jwks.json",
		ManifestSchema: "ocm-validator-manifest/v1",
		SessionKind:    SessionKindPassiveOnly,
		TerminalReason: &reason,
		FinishedAt:     &finished,
		CreatedAt:      finished,
		UpdatedAt:      finished,
	}

	if err := db.WithContext(ctx).Create(row).Error; err != nil {
		t.Fatalf("seed %s: %v", id, err)
	}
}

// seedPruneChildRows attaches a full set of validator-owned child artifacts to
// the aged terminal run and one exchange to the recent run.
func seedPruneChildRows(t *testing.T, db *gorm.DB) {
	t.Helper()

	mustExec(t, db, `INSERT INTO share_correlation
		(test_run_id, role, sender_host, provider_id, local_identity, status, created_at)
		VALUES ('run-prune-stale', 'outgoing_to_target', 'target.example', 'prov-prune', 'a', 'confirmed', 1)`)
	mustExec(t, db, `INSERT INTO report_exchange
		(test_run_id, seq, captured_at, direction, actor, endpoint_id, method, url, created_at)
		VALUES ('run-prune-stale', 1, 1, 'out', 'validator', 'discovery', 'GET', 'https://target.example/x', 1)`)
	mustExec(t, db, `INSERT INTO evidence_row
		(test_run_id, area, step, reason_code, severity, affects_grade, exchange_id, created_at)
		VALUES ('run-prune-stale', 'http', 'request', 'timeout', 'important', TRUE, 1, 1)`)
	mustExec(t, db, `INSERT INTO dispatch_reservation
		(test_run_id, provider_id, webdav_id, shared_secret, receiver_host, share_with, probe_file_path, status, created_at)
		VALUES ('run-prune-stale', 'prov-prune', 'wd-prune', 'secret', 'receiver.example', 'bob', '/probe.bin', 'dispatch_reserved', 1)`)
	mustExec(t, db, `INSERT INTO report_exchange
		(test_run_id, seq, captured_at, direction, actor, endpoint_id, method, url, created_at)
		VALUES ('run-prune-recent', 1, 1, 'out', 'validator', 'discovery', 'GET', 'https://target.example/y', 1)`)
}

// seedRunChildSet attaches one row of each validator-owned child table to
// runID, so prune tests can prove which runs get their artifacts harvested.
// The evidence row points at the exchange row inserted just before it, which
// is exchange_id 1 in a fresh database.
func seedRunChildSet(t *testing.T, db *gorm.DB, runID string) {
	t.Helper()

	mustExec(t, db, `INSERT INTO share_correlation
		(test_run_id, role, sender_host, provider_id, local_identity, status, created_at)
		VALUES ('`+runID+`', 'outgoing_to_target', 'target.example', 'prov-`+runID+`', 'a', 'confirmed', 1)`)
	mustExec(t, db, `INSERT INTO report_exchange
		(test_run_id, seq, captured_at, direction, actor, endpoint_id, method, url, created_at)
		VALUES ('`+runID+`', 1, 1, 'out', 'validator', 'discovery', 'GET', 'https://target.example/x', 1)`)
	mustExec(t, db, `INSERT INTO evidence_row
		(test_run_id, area, step, reason_code, severity, affects_grade, exchange_id, created_at)
		VALUES ('`+runID+`', 'http', 'request', 'timeout', 'important', TRUE, 1, 1)`)
	mustExec(t, db, `INSERT INTO dispatch_reservation
		(test_run_id, provider_id, webdav_id, shared_secret, receiver_host, share_with, probe_file_path, status, created_at)
		VALUES ('`+runID+`', 'prov-`+runID+`', 'wd-`+runID+`', 'secret', 'receiver.example', 'bob', '/probe.bin', 'dispatch_reserved', 1)`)
}

func assertChildRowCount(t *testing.T, db *gorm.DB, table, runID string, want int64) {
	t.Helper()

	var count int64

	mustQueryCount(t, db, "SELECT COUNT(*) FROM "+table+" WHERE test_run_id = '"+runID+"'", &count)

	if count != want {
		t.Fatalf("%s rows for %s = %d, want %d", table, runID, count, want)
	}
}

func assertTombstone(t *testing.T, core *Core, runID, wantReason string, wantFinished int64) {
	t.Helper()

	got, err := core.GetTestRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetTestRun %s: %v (tombstone must keep the row)", runID, err)
	}

	if got.IsActive {
		t.Fatalf("%s is_active = 1, want 0", runID)
	}

	if got.HarvestedAt == nil {
		t.Fatalf("%s harvested_at is NULL, want stamped", runID)
	}

	if got.HarvestReason == nil || *got.HarvestReason != "retention_expired" {
		t.Fatalf("%s harvest_reason = %v, want retention_expired", runID, got.HarvestReason)
	}

	if got.State != StateTerminalPass {
		t.Fatalf("%s state = %q, want unchanged %q", runID, got.State, StateTerminalPass)
	}

	if got.TerminalReason == nil || *got.TerminalReason != wantReason {
		t.Fatalf("%s terminal_reason = %v, want unchanged %q", runID, got.TerminalReason, wantReason)
	}

	if got.FinishedAt == nil || *got.FinishedAt != wantFinished {
		t.Fatalf("%s finished_at = %v, want unchanged %d", runID, got.FinishedAt, wantFinished)
	}

	if got.UpdatedAt != wantFinished {
		t.Fatalf("%s updated_at = %d, want unchanged %d", runID, got.UpdatedAt, wantFinished)
	}
}

func assertNoTombstone(t *testing.T, core *Core, runID, wantState string) {
	t.Helper()

	got, err := core.GetTestRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetTestRun %s: %v", runID, err)
	}

	if got.State != wantState {
		t.Fatalf("%s state = %q, want unchanged %q", runID, got.State, wantState)
	}

	if got.HarvestedAt != nil || got.HarvestReason != nil {
		t.Fatalf("%s tombstone = (%v, %v), want both NULL", runID, got.HarvestedAt, got.HarvestReason)
	}
}
