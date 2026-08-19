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
			SessionKind:    SessionKindPassiveOnly,
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
	for i, state := range []string{"", "RUNNING", "terminal_unknown", "active"} {
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
		"discovery_url", "jwks_uri", "terminal_reason", "finished_at",
		"overall_grade", "manifest_schema", "manifest_json", "session_kind",
		"created_at", "updated_at",
		"bob_user_id", "reverse_invite_token", "reverse_invite_imported_at",
		"designated_share_with", "reverse_share_provider_id", "stats_written_at",
		"opt_in_stats", "opt_in_permanent", "opt_in_stats_channel", "opt_in_stats_at",
		"opt_in_permanent_channel", "opt_in_permanent_at", "retention_tier",
		"retention_locked_at", "expires_at", "permanent_report_id", "harvested_at",
		"harvested_session_artifacts_at", "harvest_reason",
	}

	for _, col := range expected {
		if _, ok := info[col]; !ok {
			t.Fatalf("test_run missing column %s", col)
		}
	}

	forbidden := []string{"is_permanent", "alice_storage_root", "probe_file_path"}

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

	if !info["opt_in_stats"].NotNull || !info["opt_in_permanent"].NotNull {
		t.Fatal("opt_in_stats and opt_in_permanent must be NOT NULL")
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

	for _, col := range []string{"opt_in_stats", "opt_in_permanent"} {
		if !info[col].NotNull {
			t.Fatalf("%s must be NOT NULL", col)
		}

		if info[col].DfltValue == nil || *info[col].DfltValue != "0" {
			t.Fatalf("%s must default to 0, got %+v", col, info[col])
		}
	}

	mustExec(t, db, `INSERT INTO test_run
		(test_run_id, is_active, state, target_origin, target_host, discovery_url, jwks_uri,
		 manifest_schema, session_kind, created_at, updated_at)
		VALUES ('run-defaults', FALSE, 'created', 'https://t.example', 't.example',
		 'https://t.example/.well-known/ocm', 'https://t.example/jwks.json',
		 'ocm-validator-manifest/v1', 'passive_only', 1, 1)`)

	var optInStats, optInPermanent bool

	row := db.Raw(
		"SELECT opt_in_stats, opt_in_permanent FROM test_run WHERE test_run_id = 'run-defaults'",
	).Row()
	if err := row.Scan(&optInStats, &optInPermanent); err != nil {
		t.Fatalf("read opt-in defaults: %v", err)
	}

	if optInStats || optInPermanent {
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
