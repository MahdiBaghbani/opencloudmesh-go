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
