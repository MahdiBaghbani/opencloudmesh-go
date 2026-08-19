// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// ocmgo:file-length-ignore: passive session lifecycle, extension guards, sweeps, TTL, and collision coverage

package validatorcore

import (
	"errors"
	"testing"
	"time"

	"gorm.io/gorm"

	store "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
)

func TestCreatePassiveSession_EnforcesInFlightCap(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.sessionCfg = SessionConfig{InFlightPassiveLimit: 1}
	ctx := t.Context()
	now := time.Now().Unix()

	first := &TestRun{
		TestRunID:   "run-cap-1",
		State:       StateCreated,
		SessionKind: SessionKindPassiveOnly,
		TargetHost:  "peer.example",
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := core.CreatePassiveSession(ctx, first); err != nil {
		t.Fatalf("create first: %v", err)
	}

	second := &TestRun{
		TestRunID:   "run-cap-2",
		State:       StateCreated,
		SessionKind: SessionKindPassiveOnly,
		TargetHost:  "peer2.example",
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	err := core.CreatePassiveSession(ctx, second)
	if !errors.Is(err, ErrInFlightPassiveLimit) {
		t.Fatalf("create second error = %v, want ErrInFlightPassiveLimit", err)
	}
}

func TestPassiveProbeTransitions(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	now := time.Now().Unix()
	runID := "run-probe"

	row := &TestRun{
		TestRunID:   runID,
		State:       StateCreated,
		SessionKind: SessionKindPassiveOnly,
		TargetHost:  "probe.example",
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := core.CreatePassiveSession(ctx, row); err != nil {
		t.Fatalf("create: %v", err)
	}

	if err := core.RunStartProbe(ctx, runID); err != nil {
		t.Fatalf("RunStartProbe: %v", err)
	}

	got, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if got.State != StatePassiveRunning {
		t.Fatalf("state = %q, want %q", got.State, StatePassiveRunning)
	}

	if completeErr := core.CompletePassiveProbe(ctx, runID); completeErr != nil {
		t.Fatalf("CompletePassiveProbe: %v", completeErr)
	}

	got, err = core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun after complete: %v", err)
	}

	if got.State != StatePassiveComplete {
		t.Fatalf("state = %q, want %q", got.State, StatePassiveComplete)
	}
}

func TestExtendToActive_RequiresPassiveComplete(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	now := time.Now().Unix()
	runID := "run-extend-not-ready"

	row := &TestRun{
		TestRunID:   runID,
		State:       StateCreated,
		SessionKind: SessionKindPassiveOnly,
		TargetHost:  "extend.example",
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := core.CreatePassiveSession(ctx, row); err != nil {
		t.Fatalf("create: %v", err)
	}

	err := core.ExtendToActive(ctx, runID)
	if !errors.Is(err, ErrSessionNotReady) {
		t.Fatalf("ExtendToActive error = %v, want ErrSessionNotReady", err)
	}
}

func TestExtendToActive_ConflictsWithOneActiveLock(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	now := time.Now().Unix()

	for _, id := range []string{"run-active-a", "run-active-b"} {
		row := &TestRun{
			TestRunID:   id,
			State:       StatePassiveComplete,
			SessionKind: SessionKindPassiveOnly,
			TargetHost:  "lock.example",
			CreatedAt:   now,
			UpdatedAt:   now,
		}

		if err := core.DB().WithContext(ctx).Create(row).Error; err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}

	if err := core.ExtendToActive(ctx, "run-active-a"); err != nil {
		t.Fatalf("first extend: %v", err)
	}

	extendErr := core.ExtendToActive(ctx, "run-active-b")

	var storeErr *StoreError
	if !errors.As(extendErr, &storeErr) || storeErr.Op != OpExtendUpdate {
		t.Fatalf("second extend error = %v, want OpExtendUpdate store error", extendErr)
	}
}

func TestExtendToActive_TerminalStateReturnsSessionNotReady(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	now := time.Now().Unix()
	runID := "run-extend-terminal"

	row := &TestRun{
		TestRunID:   runID,
		State:       StateTerminalPass,
		SessionKind: SessionKindPassiveOnly,
		TargetHost:  "terminal.example",
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := core.DB().WithContext(ctx).Create(row).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	err := core.ExtendToActive(ctx, runID)
	if !errors.Is(err, ErrSessionNotReady) {
		t.Fatalf("ExtendToActive error = %v, want ErrSessionNotReady", err)
	}

	if errors.Is(err, ErrStopSessionMiss) {
		t.Fatalf("ExtendToActive must not return ErrStopSessionMiss for terminal state")
	}
}

func TestExtendToActive_RepeatedExtensionReturnsInteractiveConflict(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	now := time.Now().Unix()
	runID := "run-repeat-extend"

	row := &TestRun{
		TestRunID:   runID,
		State:       StatePassiveComplete,
		SessionKind: SessionKindPassiveOnly,
		TargetHost:  "repeat.example",
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := core.DB().WithContext(ctx).Create(row).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	if err := core.ExtendToActive(ctx, runID); err != nil {
		t.Fatalf("first extend: %v", err)
	}

	err := core.ExtendToActive(ctx, runID)
	if !errors.Is(err, ErrInteractiveRunInProgress) {
		t.Fatalf("repeat extend error = %v, want ErrInteractiveRunInProgress", err)
	}
}

func TestEnterTerminalState_PassiveGuard(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	now := time.Now().Unix()
	runID := "run-terminal"

	row := &TestRun{
		TestRunID:   runID,
		State:       StatePassiveComplete,
		SessionKind: SessionKindPassiveOnly,
		TargetHost:  "terminal.example",
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := core.DB().WithContext(ctx).Create(row).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	if err := core.StopPassiveComplete(ctx, runID); err != nil {
		t.Fatalf("StopPassiveComplete: %v", err)
	}

	got, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if got.State != StateTerminalPass {
		t.Fatalf("state = %q, want %q", got.State, StateTerminalPass)
	}

	if got.SessionKind != SessionKindPassiveOnly {
		t.Fatalf("session_kind = %q, want passive_only", got.SessionKind)
	}
}

func TestStartupSweep_TerminalizesExpiredPassiveInFlight(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.sessionCfg = SessionConfig{
		InFlightPassiveLimit:      10,
		CreatedTTLSeconds:         60,
		PassiveRunningTTLSeconds:  60,
		PassiveCompleteTTLSeconds: 60,
		TerminalRetentionDays:     30,
	}

	ctx := t.Context()
	stale := time.Now().Add(-2 * time.Minute).Unix()

	row := &TestRun{
		TestRunID:   "run-sweep",
		State:       StatePassiveRunning,
		SessionKind: SessionKindPassiveOnly,
		TargetHost:  "sweep.example",
		CreatedAt:   stale,
		UpdatedAt:   stale,
	}

	if err := core.DB().WithContext(ctx).Create(row).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	if err := core.sweepPassiveInFlightTTL(ctx); err != nil {
		t.Fatalf("sweepPassiveInFlightTTL: %v", err)
	}

	got, err := core.GetTestRun(ctx, "run-sweep")
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if got.State != StateTerminalFail {
		t.Fatalf("state = %q, want terminal_fail", got.State)
	}

	if got.SessionKind != SessionKindPassiveOnly {
		t.Fatalf("session_kind = %q, want passive_only", got.SessionKind)
	}
}

func TestSweepPassiveCompleteTTL_TerminalizesExpiredSession(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.sessionCfg = SessionConfig{
		InFlightPassiveLimit:      10,
		PassiveCompleteTTLSeconds: 60,
	}

	ctx := t.Context()
	stale := time.Now().Add(-2 * time.Minute).Unix()

	row := &TestRun{
		TestRunID:   "run-pc-sweep",
		IsActive:    false,
		State:       StatePassiveComplete,
		SessionKind: SessionKindPassiveOnly,
		TargetHost:  "pc.example",
		CreatedAt:   stale,
		UpdatedAt:   stale,
	}

	if err := core.DB().WithContext(ctx).Create(row).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	if err := core.sweepPassiveCompleteTTL(ctx); err != nil {
		t.Fatalf("sweepPassiveCompleteTTL: %v", err)
	}

	got, err := core.GetTestRun(ctx, "run-pc-sweep")
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if got.State != StateTerminalFail {
		t.Fatalf("state = %q, want %q", got.State, StateTerminalFail)
	}

	if got.SessionKind != SessionKindPassiveOnly {
		t.Fatalf("session_kind = %q, want %q", got.SessionKind, SessionKindPassiveOnly)
	}

	if got.TerminalReason == nil || *got.TerminalReason != "passive_complete_ttl_expired" {
		t.Fatalf("terminal_reason = %v, want passive_complete_ttl_expired", got.TerminalReason)
	}

	if got.FinishedAt == nil {
		t.Fatal("expected finished_at to be set")
	}
}

func TestSweepPassiveInFlightTTL_ReleasesInFlightCount(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.sessionCfg = SessionConfig{
		InFlightPassiveLimit:     1,
		CreatedTTLSeconds:        60,
		PassiveRunningTTLSeconds: 60,
	}

	ctx := t.Context()
	stale := time.Now().Add(-2 * time.Minute).Unix()

	rows := []struct {
		id     string
		state  string
		reason string
	}{
		{id: "run-sweep-created", state: StateCreated, reason: "created_ttl_expired"},
		{id: "run-sweep-running", state: StatePassiveRunning, reason: "passive_running_ttl_expired"},
	}

	for _, item := range rows {
		row := &TestRun{
			TestRunID:   item.id,
			IsActive:    false,
			State:       item.state,
			SessionKind: SessionKindPassiveOnly,
			TargetHost:  "cap.example",
			CreatedAt:   stale,
			UpdatedAt:   stale,
		}

		if err := core.DB().WithContext(ctx).Create(row).Error; err != nil {
			t.Fatalf("seed %s: %v", item.id, err)
		}
	}

	before, err := core.CountInFlightPassive(ctx)
	if err != nil {
		t.Fatalf("CountInFlightPassive before sweep: %v", err)
	}

	if before != 2 {
		t.Fatalf("in-flight count before sweep = %d, want 2", before)
	}

	if sweepErr := core.sweepPassiveInFlightTTL(ctx); sweepErr != nil {
		t.Fatalf("sweepPassiveInFlightTTL: %v", sweepErr)
	}

	after, err := core.CountInFlightPassive(ctx)
	if err != nil {
		t.Fatalf("CountInFlightPassive after sweep: %v", err)
	}

	if after != 0 {
		t.Fatalf("in-flight count after sweep = %d, want 0", after)
	}

	for _, item := range rows {
		got, getErr := core.GetTestRun(ctx, item.id)
		if getErr != nil {
			t.Fatalf("GetTestRun %s: %v", item.id, getErr)
		}

		if got.State != StateTerminalFail {
			t.Fatalf("%s state = %q, want %q", item.id, got.State, StateTerminalFail)
		}

		if got.SessionKind != SessionKindPassiveOnly {
			t.Fatalf("%s session_kind = %q, want %q", item.id, got.SessionKind, SessionKindPassiveOnly)
		}

		if got.TerminalReason == nil || *got.TerminalReason != item.reason {
			t.Fatalf("%s terminal_reason = %v, want %q", item.id, got.TerminalReason, item.reason)
		}
	}
}

func TestSweepPassiveInFlightTTL_LeavesActiveInFlightUntouched(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.sessionCfg = SessionConfig{
		InFlightPassiveLimit:      10,
		CreatedTTLSeconds:         60,
		PassiveRunningTTLSeconds:  60,
		PassiveCompleteTTLSeconds: 60,
	}

	ctx := t.Context()
	stale := time.Now().Add(-2 * time.Minute).Unix()

	row := &TestRun{
		TestRunID:   "run-lb7-active",
		IsActive:    true,
		State:       StatePassiveRunning,
		SessionKind: SessionKindPassiveOnly,
		TargetHost:  "lb7.example",
		CreatedAt:   stale,
		UpdatedAt:   stale,
	}

	if err := core.DB().WithContext(ctx).Create(row).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	before, err := core.GetTestRun(ctx, "run-lb7-active")
	if err != nil {
		t.Fatalf("GetTestRun before sweep: %v", err)
	}

	if sweepErr := core.sweepPassiveInFlightTTL(ctx); sweepErr != nil {
		t.Fatalf("sweepPassiveInFlightTTL: %v", sweepErr)
	}

	if completeErr := core.sweepPassiveCompleteTTL(ctx); completeErr != nil {
		t.Fatalf("sweepPassiveCompleteTTL: %v", completeErr)
	}

	got, err := core.GetTestRun(ctx, "run-lb7-active")
	if err != nil {
		t.Fatalf("GetTestRun after sweep: %v", err)
	}

	if got.State != before.State {
		t.Fatalf("state = %q, want unchanged %q", got.State, before.State)
	}

	if got.IsActive != before.IsActive {
		t.Fatalf("is_active = %v, want unchanged %v", got.IsActive, before.IsActive)
	}

	if got.UpdatedAt != before.UpdatedAt {
		t.Fatalf("updated_at = %d, want unchanged %d", got.UpdatedAt, before.UpdatedAt)
	}

	if got.TerminalReason != nil {
		t.Fatalf("terminal_reason = %v, want nil", got.TerminalReason)
	}

	if got.FinishedAt != nil {
		t.Fatalf("finished_at = %v, want nil", got.FinishedAt)
	}
}

func TestCreatePassiveSession_PKCollisionIsStoreError(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	now := time.Now().Unix()

	row := &TestRun{
		TestRunID:   "run-dup",
		State:       StateCreated,
		SessionKind: SessionKindPassiveOnly,
		TargetHost:  "dup.example",
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := core.CreatePassiveSession(ctx, row); err != nil {
		t.Fatalf("first create: %v", err)
	}

	dupErr := core.CreatePassiveSession(ctx, row)

	var storeErr *StoreError
	if !errors.As(dupErr, &storeErr) || storeErr.Op != OpCreateSessionInsert {
		t.Fatalf("duplicate create error = %v, want OpCreateSessionInsert", dupErr)
	}

	if !errors.Is(storeErr.Err, gorm.ErrDuplicatedKey) {
		t.Fatalf("wrapped error = %v, want gorm.ErrDuplicatedKey", storeErr.Err)
	}
}

func TestPruneTerminalSessions_CascadesChildArtifacts(t *testing.T) {
	t.Parallel()

	// sqlitecore enables PRAGMA foreign_keys on every connection, so this
	// store enforces the cascade contract the way production does.
	sqlCore := openPeerStore(t)

	core, err := Attach(sqlCore.DB(), DefaultSessionConfig())
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}

	db := core.DB()
	ctx := t.Context()

	var fkEnforced int

	if err := db.Raw("PRAGMA foreign_keys").Scan(&fkEnforced).Error; err != nil {
		t.Fatalf("read foreign_keys pragma: %v", err)
	}

	if fkEnforced != 1 {
		t.Fatalf("foreign_keys = %d, want 1 (cascade proof requires enforcement)", fkEnforced)
	}

	now := time.Now().Unix()
	staleFinished := now - int64(60*24*3600)
	recentFinished := now - 3600

	seedRun := func(id string, finished int64) {
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
			FinishedAt:     &finished,
			CreatedAt:      finished,
			UpdatedAt:      finished,
		}

		if err := db.WithContext(ctx).Create(row).Error; err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}

	seedRun("run-prune-stale", staleFinished)
	seedRun("run-prune-recent", recentFinished)

	// A full set of validator-owned child artifacts on the aged terminal run.
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

	// One child on the recent run proves pruning stays inside the window.
	mustExec(t, db, `INSERT INTO report_exchange
		(test_run_id, seq, captured_at, direction, actor, endpoint_id, method, url, created_at)
		VALUES ('run-prune-recent', 1, 1, 'out', 'validator', 'discovery', 'GET', 'https://target.example/y', 1)`)

	// Peer persistence shares the database and must never be touched.
	peer := store.OutgoingShare{
		ShareID:    "share-prune",
		ProviderID: "provider-prune",
		WebDAVID:   "webdav-prune",
		CreatedAt:  1,
	}

	if err := db.WithContext(ctx).Create(&peer).Error; err != nil {
		t.Fatalf("seed peer row: %v", err)
	}

	if err := core.PruneTerminalSessions(ctx, 30); err != nil {
		t.Fatalf("PruneTerminalSessions with child rows: %v", err)
	}

	for _, table := range []string{
		"test_run", "share_correlation", "report_exchange", "evidence_row", "dispatch_reservation",
	} {
		var count int64

		mustQueryCount(t, db, "SELECT COUNT(*) FROM "+table+" WHERE test_run_id = 'run-prune-stale'", &count)

		if count != 0 {
			t.Fatalf("%s rows for pruned run = %d, want 0 (cascade)", table, count)
		}
	}

	var recentCount, recentExCount, peerCount int64

	mustQueryCount(t, db, "SELECT COUNT(*) FROM test_run WHERE test_run_id = 'run-prune-recent'", &recentCount)
	mustQueryCount(t, db, "SELECT COUNT(*) FROM report_exchange WHERE test_run_id = 'run-prune-recent'", &recentExCount)
	mustQueryCount(t, db, "SELECT COUNT(*) FROM outgoing_shares WHERE share_id = 'share-prune'", &peerCount)

	if recentCount != 1 || recentExCount != 1 {
		t.Fatalf(
			"recent run = %d rows, %d exchanges; want 1 each (inside retention window)",
			recentCount,
			recentExCount,
		)
	}

	if peerCount != 1 {
		t.Fatalf("peer outgoing_shares rows = %d, want 1 (peer tables untouched)", peerCount)
	}
}
