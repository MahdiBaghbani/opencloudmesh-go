// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"fmt"
	"strings"
	"testing"
)

func TestTestRunStateCheck_ExactStates(t *testing.T) {
	t.Parallel()

	db := attachFresh(t)
	sqlText := tableSQL(t, db, "test_run")

	// The DDL must name exactly the live state list: every live value present,
	// every dormant value absent.
	for _, state := range testRunStates {
		if !strings.Contains(sqlText, "'"+state+"'") {
			t.Fatalf("test_run CHECK missing live state %q", state)
		}
	}

	for _, state := range dormantTestRunStates {
		if strings.Contains(sqlText, "'"+state+"'") {
			t.Fatalf("test_run CHECK must not contain dormant state %q", state)
		}
	}

	newRun := func(id, state string) TestRun {
		return TestRun{
			TestRunID:      id,
			State:          state,
			TargetOrigin:   "https://t.example",
			TargetHost:     "t.example",
			DiscoveryURL:   "https://t.example/.well-known/ocm",
			JwksURI:        "https://t.example/jwks.json",
			ManifestSchema: "ocm-validator-manifest/v1",
			CreatedAt:      1,
			UpdatedAt:      1,
		}
	}

	// Every live state name must be accepted by the CHECK constraint.
	for i, state := range testRunStates {
		run := newRun(fmt.Sprintf("run-live-%d", i), state)
		if err := db.Create(&run).Error; err != nil {
			t.Fatalf("live state %q must be accepted: %v", state, err)
		}
	}

	// Every dormant state name must be rejected.
	for i, state := range dormantTestRunStates {
		run := newRun(fmt.Sprintf("run-dormant-%d", i), state)
		if err := db.Create(&run).Error; err == nil {
			t.Fatalf("dormant state %q must be rejected by the CHECK constraint", state)
		}
	}

	// Arbitrary values outside the live list must be rejected.
	for i, state := range []string{
		"",
		"RUNNING",
		"terminal_unknown",
		"active",
		"reverse_invite_solicited",
		"reverse_invite_imported",
	} {
		run := newRun(fmt.Sprintf("run-arbitrary-%d", i), state)
		if err := db.Create(&run).Error; err == nil {
			t.Fatalf("arbitrary state %q must be rejected by the CHECK constraint", state)
		}
	}
}

func TestTestRun_FinalColumns(t *testing.T) {
	t.Parallel()

	db := attachFresh(t)
	info := tableInfo(t, db, "test_run")

	expected := []string{
		"test_run_id", "is_active", "state", "target_origin", "target_host",
		"remote_ocm_id", "discovery_url", "jwks_uri", "platform", "api_version",
		"terminal_reason", "finished_at", "overall_grade", "manifest_schema",
		"manifest_json", "bob_user_id", "outgoing_invite_id", "s1_claimed_at",
		"reverse_invite_token", "reverse_invite_imported_at",
		"designated_share_with", "reverse_share_provider_id", "passive_ready_at",
		"stats_written_at", "opt_in_stats", "opt_in_permanent", "opt_in_active",
		"opt_in_stats_channel", "opt_in_stats_at", "opt_in_permanent_channel",
		"opt_in_permanent_at", "opt_in_active_channel", "opt_in_active_at",
		"retention_tier", "retention_locked_at", "expires_at",
		"permanent_report_id", "harvested_at", "harvested_session_artifacts_at",
		"harvest_reason", "created_at", "updated_at",
	}

	if len(info) != 42 {
		t.Fatalf("test_run has %d columns, want 42", len(info))
	}

	for _, col := range expected {
		if _, ok := info[col]; !ok {
			t.Fatalf("test_run missing column %s", col)
		}
	}

	forbidden := []string{"is_permanent", "alice_storage_root", "probe_file_path", "session_kind"}

	for _, col := range forbidden {
		if _, ok := info[col]; ok {
			t.Fatalf("test_run must not have column %s", col)
		}
	}

	if info["test_run_id"].PK != 1 {
		t.Fatal("test_run_id must be the primary key")
	}

	if info["bob_user_id"].NotNull {
		t.Fatal("bob_user_id must be nullable")
	}

	if !info["opt_in_stats"].NotNull || !info["opt_in_permanent"].NotNull || !info["opt_in_active"].NotNull {
		t.Fatal("opt_in_stats, opt_in_permanent, and opt_in_active must be NOT NULL")
	}

	if info["jwks_uri"].NotNull {
		t.Fatal("jwks_uri must be nullable")
	}

	if info["remote_ocm_id"].NotNull || info["outgoing_invite_id"].NotNull {
		t.Fatal("remote_ocm_id and outgoing_invite_id must be nullable")
	}
}

func TestTestRun_OneActivePartialUniqueIndex(t *testing.T) {
	t.Parallel()

	db := attachFresh(t)

	var indexSQL string

	if err := db.Raw(
		"SELECT sql FROM sqlite_master WHERE type = 'index' AND name = 'idx_test_run_one_active'",
	).Scan(&indexSQL).Error; err != nil {
		t.Fatalf("read index sql: %v", err)
	}

	if indexSQL == "" {
		t.Fatal("idx_test_run_one_active index missing")
	}

	if !strings.Contains(strings.ToUpper(indexSQL), "WHERE") {
		t.Fatalf("idx_test_run_one_active must be partial: %s", indexSQL)
	}

	createTestRun(t, db, "run-active-1")
	mustExec(t, db, "UPDATE test_run SET is_active = TRUE WHERE test_run_id = 'run-active-1'")
	createTestRun(t, db, "run-active-2")

	if err := db.Exec("UPDATE test_run SET is_active = TRUE WHERE test_run_id = 'run-active-2'").Error; err == nil {
		t.Fatal("second active run must violate the partial unique index")
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

	// idx_test_run_one_active still caps the table at one is_active=1 row.
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
		t.Fatal("second active run must violate idx_test_run_one_active")
	}
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

func TestTestRun_OptInDefaults(t *testing.T) {
	t.Parallel()

	db := attachFresh(t)
	info := tableInfo(t, db, "test_run")

	for _, col := range []string{"opt_in_stats", "opt_in_permanent", "opt_in_active"} {
		if !info[col].NotNull {
			t.Fatalf("%s must be NOT NULL", col)
		}

		if info[col].DfltValue == nil || *info[col].DfltValue != "0" {
			t.Fatalf("%s must default to 0, got %+v", col, info[col])
		}
	}

	mustExec(t, db, `INSERT INTO test_run
		(test_run_id, is_active, state, target_origin, target_host, discovery_url,
		 manifest_schema, created_at, updated_at)
		VALUES ('run-defaults', FALSE, 'created', 'https://t.example', 't.example',
		 'https://t.example/.well-known/ocm',
		 'ocm-validator-manifest/v1', 1, 1)`)

	var optInStats, optInPermanent, optInActive bool

	row := db.Raw(
		"SELECT opt_in_stats, opt_in_permanent, opt_in_active FROM test_run WHERE test_run_id = 'run-defaults'",
	).Row()
	if err := row.Scan(&optInStats, &optInPermanent, &optInActive); err != nil {
		t.Fatalf("read opt-in defaults: %v", err)
	}

	if optInStats || optInPermanent || optInActive {
		t.Fatal("opt-in columns must default to 0 when omitted from the insert")
	}
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
		"idx_test_run_one_active",
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
