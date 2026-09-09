// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"strings"
	"testing"
)

func TestTestRun_ActivePerTargetPartialUniqueIndex(t *testing.T) {
	t.Parallel()

	db := attachFresh(t)

	var indexSQL string

	if err := db.Raw(
		"SELECT sql FROM sqlite_master WHERE type = 'index' AND name = 'idx_test_run_active_per_target'",
	).Scan(&indexSQL).Error; err != nil {
		t.Fatalf("read index sql: %v", err)
	}

	if indexSQL == "" {
		t.Fatal("idx_test_run_active_per_target index missing")
	}

	if !strings.Contains(strings.ToUpper(indexSQL), "WHERE") {
		t.Fatalf("idx_test_run_active_per_target must be partial: %s", indexSQL)
	}

	if !strings.Contains(indexSQL, "(target_host)") {
		t.Fatalf("active-per-target index must unique on target_host: %s", indexSQL)
	}

	if !strings.Contains(indexSQL, "is_active = 1") {
		t.Fatalf("active-per-target index must be partial on is_active = 1: %s", indexSQL)
	}

	createTestRun(t, db, "run-active-1")
	mustExec(t, db, "UPDATE test_run SET is_active = TRUE WHERE test_run_id = 'run-active-1'")
	createTestRun(t, db, "run-active-2")

	if err := db.Exec("UPDATE test_run SET is_active = TRUE WHERE test_run_id = 'run-active-2'").Error; err == nil {
		t.Fatal("second active run on the same target_host must violate idx_test_run_active_per_target")
	}

	mustExec(t, db, `INSERT INTO test_run
		(test_run_id, is_active, state, target_origin, target_host, discovery_url,
		 manifest_schema, created_at, updated_at)
		VALUES ('run-active-other', 1, 'active_running', 'https://other.example', 'other.example',
		 'https://other.example/.well-known/ocm',
		 'ocm-validator-manifest/v1', 1, 1)`)

	var activeCount int64

	if err := db.Raw("SELECT COUNT(*) FROM test_run WHERE is_active = 1").Scan(&activeCount).Error; err != nil {
		t.Fatalf("count active runs: %v", err)
	}

	if activeCount != 2 {
		t.Fatalf("active runs = %d, want 2 across different target hosts", activeCount)
	}
}

func TestTestRun_BobUserIDPartialUniqueIndex(t *testing.T) {
	t.Parallel()

	db := attachFresh(t)

	var indexSQL string

	if err := db.Raw(
		"SELECT sql FROM sqlite_master WHERE type = 'index' AND name = 'idx_test_run_bob_user_id'",
	).Scan(&indexSQL).Error; err != nil {
		t.Fatalf("read index sql: %v", err)
	}

	if indexSQL == "" {
		t.Fatal("idx_test_run_bob_user_id index missing")
	}

	if !strings.Contains(strings.ToUpper(indexSQL), "UNIQUE") {
		t.Fatalf("idx_test_run_bob_user_id must be unique: %s", indexSQL)
	}

	if !strings.Contains(strings.ToUpper(indexSQL), "WHERE") {
		t.Fatalf("idx_test_run_bob_user_id must be partial: %s", indexSQL)
	}

	if !strings.Contains(indexSQL, "bob_user_id IS NOT NULL") {
		t.Fatalf("idx_test_run_bob_user_id must be partial on bob_user_id IS NOT NULL: %s", indexSQL)
	}

	createTestRun(t, db, "run-bob-1")
	createTestRun(t, db, "run-bob-2")
	createTestRun(t, db, "run-bob-3")

	mustExec(t, db, "UPDATE test_run SET bob_user_id = 'bob-1' WHERE test_run_id = 'run-bob-1'")
	mustExec(t, db, "UPDATE test_run SET bob_user_id = 'bob-2' WHERE test_run_id = 'run-bob-2'")

	if err := db.Exec(
		"UPDATE test_run SET bob_user_id = 'bob-1' WHERE test_run_id = 'run-bob-3'",
	).Error; err == nil {
		t.Fatal("duplicate non-null bob_user_id must be rejected")
	}

	mustExec(t, db, "UPDATE test_run SET bob_user_id = NULL WHERE test_run_id = 'run-bob-3'")

	var nullCount int64

	if err := db.Raw(
		"SELECT COUNT(*) FROM test_run WHERE bob_user_id IS NULL",
	).Scan(&nullCount).Error; err != nil {
		t.Fatalf("count null bob_user_id: %v", err)
	}

	if nullCount != 1 {
		t.Fatalf("null bob_user_id rows = %d, want 1", nullCount)
	}
}

func TestTestRun_OptInActiveReadyPartialUniqueIndex(t *testing.T) {
	t.Parallel()

	db := attachFresh(t)

	var indexSQL string

	if err := db.Raw(
		"SELECT sql FROM sqlite_master WHERE type = 'index' AND name = 'idx_test_run_opt_in_active_ready'",
	).Scan(&indexSQL).Error; err != nil {
		t.Fatalf("read index sql: %v", err)
	}

	if indexSQL == "" {
		t.Fatal("idx_test_run_opt_in_active_ready index missing")
	}

	if !strings.Contains(strings.ToUpper(indexSQL), "WHERE") {
		t.Fatalf("idx_test_run_opt_in_active_ready must be partial: %s", indexSQL)
	}

	if !strings.Contains(indexSQL, "(test_run_id)") {
		t.Fatalf("ready index must unique on test_run_id: %s", indexSQL)
	}

	if strings.Contains(indexSQL, "(opt_in_active)") {
		t.Fatalf("ready index must not unique on opt_in_active: %s", indexSQL)
	}

	// Multiple ready waiters with different test_run_id values must coexist.
	// The partial unique is a lock-wait finder, not a global one-waiter cap.
	mustExec(t, db, `INSERT INTO test_run
		(test_run_id, is_active, state, target_origin, target_host, discovery_url,
		 manifest_schema, opt_in_active, created_at, updated_at)
		VALUES ('run-ready-1', 0, 'passive_running', 'https://t.example', 't.example',
		 'https://t.example/.well-known/ocm',
		 'ocm-validator-manifest/v1', 1, 1, 1)`)

	mustExec(t, db, `INSERT INTO test_run
		(test_run_id, is_active, state, target_origin, target_host, discovery_url,
		 manifest_schema, opt_in_active, created_at, updated_at)
		VALUES ('run-ready-2', 0, 'passive_running', 'https://t.example', 't.example',
		 'https://t.example/.well-known/ocm',
		 'ocm-validator-manifest/v1', 1, 1, 1)`)

	var readyCount int64

	if err := db.Raw(
		"SELECT COUNT(*) FROM test_run WHERE opt_in_active = 1 AND is_active = 0 AND state = 'passive_running'",
	).Scan(&readyCount).Error; err != nil {
		t.Fatalf("count ready waiters: %v", err)
	}

	if readyCount != 2 {
		t.Fatalf("ready waiters = %d, want 2", readyCount)
	}

	// idx_test_run_active_per_target caps one is_active=1 row per target_host.
	mustExec(t, db, `INSERT INTO test_run
		(test_run_id, is_active, state, target_origin, target_host, discovery_url,
		 manifest_schema, opt_in_active, created_at, updated_at)
		VALUES ('run-active-1', 1, 'active_running', 'https://t.example', 't.example',
		 'https://t.example/.well-known/ocm',
		 'ocm-validator-manifest/v1', 1, 1, 1)`)

	if err := db.Exec(`INSERT INTO test_run
		(test_run_id, is_active, state, target_origin, target_host, discovery_url,
		 manifest_schema, opt_in_active, created_at, updated_at)
		VALUES ('run-active-2', 1, 'active_running', 'https://t.example', 't.example',
		 'https://t.example/.well-known/ocm',
		 'ocm-validator-manifest/v1', 1, 1, 1)`).Error; err == nil {
		t.Fatal("second active run on the same target_host must violate idx_test_run_active_per_target")
	}

	mustExec(t, db, `INSERT INTO test_run
		(test_run_id, is_active, state, target_origin, target_host, discovery_url,
		 manifest_schema, opt_in_active, created_at, updated_at)
		VALUES ('run-active-other', 1, 'active_running', 'https://other.example', 'other.example',
		 'https://other.example/.well-known/ocm',
		 'ocm-validator-manifest/v1', 1, 1, 1)`)
}

func TestTestRun_PermanentReportIDNullableUnique(t *testing.T) {
	t.Parallel()

	db := attachFresh(t)
	info := tableInfo(t, db, "test_run")

	if info["permanent_report_id"].NotNull {
		t.Fatal("permanent_report_id must be nullable")
	}

	createTestRun(t, db, "run-perm-1")
	createTestRun(t, db, "run-perm-2")
	createTestRun(t, db, "run-perm-3")

	mustExec(t, db, "UPDATE test_run SET permanent_report_id = 'report-1' WHERE test_run_id = 'run-perm-1'")

	if err := db.Exec(
		"UPDATE test_run SET permanent_report_id = 'report-1' WHERE test_run_id = 'run-perm-2'",
	).Error; err == nil {
		t.Fatal("duplicate permanent_report_id must be rejected")
	}

	// NULL values must not collide under the unique constraint.
	mustExec(t, db, "UPDATE test_run SET permanent_report_id = NULL WHERE test_run_id = 'run-perm-3'")
}

func TestTestRun_StatsHealIndexPredicate(t *testing.T) {
	t.Parallel()

	db := attachFresh(t)

	var indexSQL string

	if err := db.Raw(
		"SELECT sql FROM sqlite_master WHERE type = 'index' AND name = 'idx_test_run_stats_heal'",
	).Scan(&indexSQL).Error; err != nil {
		t.Fatalf("read stats heal index: %v", err)
	}

	if indexSQL == "" {
		t.Fatal("idx_test_run_stats_heal index missing")
	}

	if !strings.Contains(indexSQL, "opt_in_stats = 1") ||
		!strings.Contains(indexSQL, "stats_written_at IS NULL") {
		t.Fatalf("stats heal index must be partial on opted-in unwritten runs: %s", indexSQL)
	}
}

func TestTestRun_NamedIndexes(t *testing.T) {
	t.Parallel()

	db := attachFresh(t)

	for _, name := range []string{
		"idx_test_run_active_per_target",
		"idx_test_run_state",
		"idx_test_run_bob_user_id",
		"idx_test_run_expires_at",
		"idx_test_run_stats_heal",
		"idx_test_run_opt_in_active_ready",
		"idx_test_run_outgoing_invite",
	} {
		var indexSQL string
		if err := db.Raw(
			"SELECT sql FROM sqlite_master WHERE type = 'index' AND name = ?", name,
		).Scan(&indexSQL).Error; err != nil {
			t.Fatalf("read index %s: %v", name, err)
		}

		if indexSQL == "" {
			t.Fatalf("index %s missing", name)
		}
	}

	var sessionKindSQL string
	if err := db.Raw(
		"SELECT sql FROM sqlite_master WHERE type = 'index' AND name = 'idx_test_run_session_kind'",
	).Scan(&sessionKindSQL).Error; err != nil {
		t.Fatalf("probe dropped session_kind index: %v", err)
	}

	if sessionKindSQL != "" {
		t.Fatal("idx_test_run_session_kind must not exist")
	}
}

func TestTestRun_OutgoingInvitePartialUniqueIndex(t *testing.T) {
	t.Parallel()

	db := attachFresh(t)

	var indexSQL string

	if err := db.Raw(
		"SELECT sql FROM sqlite_master WHERE type = 'index' AND name = 'idx_test_run_outgoing_invite'",
	).Scan(&indexSQL).Error; err != nil {
		t.Fatalf("read outgoing invite index: %v", err)
	}

	if indexSQL == "" {
		t.Fatal("idx_test_run_outgoing_invite index missing")
	}

	if !strings.Contains(strings.ToUpper(indexSQL), "WHERE") {
		t.Fatalf("idx_test_run_outgoing_invite must be partial: %s", indexSQL)
	}

	createTestRun(t, db, "run-out-1")
	createTestRun(t, db, "run-out-2")
	createTestRun(t, db, "run-out-3")

	mustExec(t, db, "UPDATE test_run SET outgoing_invite_id = 'invite-1' WHERE test_run_id = 'run-out-1'")

	if err := db.Exec(
		"UPDATE test_run SET outgoing_invite_id = 'invite-1' WHERE test_run_id = 'run-out-2'",
	).Error; err == nil {
		t.Fatal("duplicate non-null outgoing_invite_id must be rejected")
	}

	// Multiple NULL outgoing_invite_id rows must coexist: the partial unique
	// applies only when outgoing_invite_id IS NOT NULL.
	mustExec(t, db, "UPDATE test_run SET outgoing_invite_id = NULL WHERE test_run_id = 'run-out-3'")

	var nullCount int64

	if err := db.Raw(
		"SELECT COUNT(*) FROM test_run WHERE outgoing_invite_id IS NULL",
	).Scan(&nullCount).Error; err != nil {
		t.Fatalf("count null outgoing_invite_id: %v", err)
	}

	if nullCount != 2 {
		t.Fatalf("null outgoing_invite_id rows = %d, want 2", nullCount)
	}
}

func TestTestRun_ForbiddenPassiveCompleteOptInActive(t *testing.T) {
	t.Parallel()

	db := attachFresh(t)

	err := db.Exec(`INSERT INTO test_run
		(test_run_id, is_active, state, target_origin, target_host, discovery_url,
		 manifest_schema, opt_in_active, created_at, updated_at)
		VALUES ('run-forbidden', FALSE, 'passive_complete', 'https://t.example', 't.example',
		 'https://t.example/.well-known/ocm',
		 'ocm-validator-manifest/v1', 1, 1, 1)`).Error
	if err == nil {
		t.Fatal("passive_complete with opt_in_active=1 must be rejected")
	}

	mustExec(t, db, `INSERT INTO test_run
		(test_run_id, is_active, state, target_origin, target_host, discovery_url,
		 manifest_schema, opt_in_active, created_at, updated_at)
		VALUES ('run-allowed', FALSE, 'passive_complete', 'https://t.example', 't.example',
		 'https://t.example/.well-known/ocm',
		 'ocm-validator-manifest/v1', 0, 1, 1)`)
}
