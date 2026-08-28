// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"context"
	"errors"
	"testing"
	"time"

	"gorm.io/gorm"

	store "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
)

func TestPruneTerminalSessions_HardDeletesRunAndChildren(t *testing.T) {
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

	// An old non-terminal run must never be pruned or deleted.
	nonTerminal := &TestRun{
		TestRunID:      "run-prune-nonterminal",
		State:          StatePassiveRunning,
		TargetOrigin:   "https://target.example",
		TargetHost:     "target.example",
		DiscoveryURL:   "https://target.example/.well-known/ocm",
		JwksURI:        "https://target.example/jwks.json",
		ManifestSchema: "ocm-validator-manifest/v1",
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

	assertRunHardDeleted(t, core, db, "run-prune-stale")

	// The too-recent terminal run keeps its child and is not deleted.
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

func TestPruneTerminalSessions_SkipsInterruptedTimeoutRun(t *testing.T) {
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
	timeoutReason := ReasonReverseShareTimeout
	staleReason := "probe_finished"

	// An aged non-permanent interrupted run with reverse_share_timeout
	// stays so a late reverse share can still flip it. The same prune
	// still hard-deletes an aged pass row.
	interrupted := &TestRun{
		TestRunID:      "run-prune-interrupted",
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
	}

	if createErr := db.WithContext(ctx).Create(interrupted).Error; createErr != nil {
		t.Fatalf("seed interrupted run: %v", createErr)
	}

	seedRunChildSet(t, db, "run-prune-interrupted")
	seedTerminalRun(t, db, ctx, "run-prune-stale-pass", staleFinished, staleReason)

	if pruneErr := core.PruneTerminalSessions(ctx, 30); pruneErr != nil {
		t.Fatalf("PruneTerminalSessions: %v", pruneErr)
	}

	assertNoTombstone(t, core, "run-prune-interrupted", StateInterrupted)
	assertChildRowCount(t, db, "report_exchange", "run-prune-interrupted", 1)
	assertChildRowCount(t, db, "evidence_row", "run-prune-interrupted", 1)
	assertChildRowCount(t, db, "dispatch_reservation", "run-prune-interrupted", 1)
	assertChildRowCount(t, db, "share_correlation", "run-prune-interrupted", 1)

	got, err := core.GetTestRun(ctx, "run-prune-interrupted")
	if err != nil {
		t.Fatalf("GetTestRun run-prune-interrupted: %v", err)
	}

	if got.TerminalReason == nil || *got.TerminalReason != ReasonReverseShareTimeout {
		t.Fatalf("terminal_reason = %v, want %q", got.TerminalReason, ReasonReverseShareTimeout)
	}

	assertRunHardDeleted(t, core, db, "run-prune-stale-pass")
}

func TestPruneTerminalSessions_SkipsActiveSameBootRow(t *testing.T) {
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
	staleReason := "probe_finished"

	// An aged terminal row that still holds the active lock must not be
	// reaped: prune only selects is_active=0 so a same-boot flippable
	// session stays live.
	active := &TestRun{
		TestRunID:      "run-prune-active",
		IsActive:       true,
		State:          StateInterrupted,
		TargetOrigin:   "https://target.example",
		TargetHost:     "target.example",
		DiscoveryURL:   "https://target.example/.well-known/ocm",
		JwksURI:        "https://target.example/jwks.json",
		ManifestSchema: "ocm-validator-manifest/v1",
		FinishedAt:     &staleFinished,
		CreatedAt:      staleFinished,
		UpdatedAt:      staleFinished,
	}

	if createErr := db.WithContext(ctx).Create(active).Error; createErr != nil {
		t.Fatalf("seed active interrupted run: %v", createErr)
	}

	seedRunChildSet(t, db, "run-prune-active")
	seedTerminalRun(t, db, ctx, "run-prune-inactive-stale", staleFinished, staleReason)

	if pruneErr := core.PruneTerminalSessions(ctx, 30); pruneErr != nil {
		t.Fatalf("PruneTerminalSessions: %v", pruneErr)
	}

	got, err := core.GetTestRun(ctx, "run-prune-active")
	if err != nil {
		t.Fatalf("GetTestRun run-prune-active: %v (active row must survive)", err)
	}

	if !got.IsActive {
		t.Fatal("is_active = 0, want 1")
	}

	if got.HarvestedAt != nil || got.HarvestReason != nil {
		t.Fatalf("tombstone = (%v, %v), want both NULL", got.HarvestedAt, got.HarvestReason)
	}

	assertChildRowCount(t, db, "report_exchange", "run-prune-active", 1)
	assertChildRowCount(t, db, "evidence_row", "run-prune-active", 1)
	assertChildRowCount(t, db, "dispatch_reservation", "run-prune-active", 1)
	assertChildRowCount(t, db, "share_correlation", "run-prune-active", 1)
	assertRunHardDeleted(t, core, db, "run-prune-inactive-stale")
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

	// An already-tombstoned permanent row keeps its original harvested_at
	// and harvest_reason when prune runs. Non-permanent rows are
	// hard-deleted children first by prune; only permanent rows are
	// tombstoned, and only by the retention sweep.
	harvested := &TestRun{
		TestRunID:      "run-prune-harvested",
		State:          StateTerminalPass,
		TargetOrigin:   "https://target.example",
		TargetHost:     "target.example",
		DiscoveryURL:   "https://target.example/.well-known/ocm",
		JwksURI:        "https://target.example/jwks.json",
		ManifestSchema: "ocm-validator-manifest/v1",
		FinishedAt:     &staleFinished,
		HarvestedAt:    &knownHarvested,
		HarvestReason:  &knownReason,
		OptInPermanent: true,
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

func TestPruneTerminalSessions_SkipsPermanentOptIn(t *testing.T) {
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
	staleReason := "probe_finished"

	permanent := &TestRun{
		TestRunID:      "run-prune-permanent",
		State:          StateTerminalPass,
		TargetOrigin:   "https://target.example",
		TargetHost:     "target.example",
		DiscoveryURL:   "https://target.example/.well-known/ocm",
		JwksURI:        "https://target.example/jwks.json",
		ManifestSchema: "ocm-validator-manifest/v1",
		TerminalReason: &staleReason,
		FinishedAt:     &staleFinished,
		OptInPermanent: true,
		CreatedAt:      staleFinished,
		UpdatedAt:      staleFinished,
	}

	if createErr := db.WithContext(ctx).Create(permanent).Error; createErr != nil {
		t.Fatalf("seed permanent run: %v", createErr)
	}

	seedTerminalRun(t, db, ctx, "run-prune-ordinary", staleFinished, staleReason)
	seedRunChildSet(t, db, "run-prune-permanent")

	if pruneErr := core.PruneTerminalSessions(ctx, 30); pruneErr != nil {
		t.Fatalf("PruneTerminalSessions: %v", pruneErr)
	}

	assertNoTombstone(t, core, "run-prune-permanent", StateTerminalPass)
	assertChildRowCount(t, db, "report_exchange", "run-prune-permanent", 1)
	assertChildRowCount(t, db, "evidence_row", "run-prune-permanent", 1)
	assertRunHardDeleted(t, core, db, "run-prune-ordinary")
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
		VALUES ('run-prune-stale', 'discovery', 'request', 'timeout', 'important', TRUE, 1, 1)`)
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
		VALUES ('`+runID+`', 'discovery', 'request', 'timeout', 'important', TRUE, 1, 1)`)
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

func assertRunHardDeleted(t *testing.T, core *Core, db *gorm.DB, runID string) {
	t.Helper()

	_, err := core.GetTestRun(t.Context(), runID)
	if !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("GetTestRun %s = %v, want ErrSessionNotFound", runID, err)
	}

	assertChildRowCount(t, db, "report_exchange", runID, 0)
	assertChildRowCount(t, db, "evidence_row", runID, 0)
	assertChildRowCount(t, db, "dispatch_reservation", runID, 0)
	assertChildRowCount(t, db, "share_correlation", runID, 0)
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
