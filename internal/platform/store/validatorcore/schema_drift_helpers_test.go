// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"fmt"
	"strings"
	"testing"

	"gorm.io/gorm"
)

// rebuildTable replaces a table definition in place: the drift DDL creates
// <table>_drift, the original is dropped, and the drift copy takes its name.
// Tables are empty at this point, so no data copy is needed. Dropping the
// original also drops its indexes; validation phases that run before the
// index phase still attribute the error to the drifted aspect.
func rebuildTable(t *testing.T, db *gorm.DB, table, driftDDL string) {
	t.Helper()

	mustExec(t, db, driftDDL)
	mustExec(t, db, "DROP TABLE "+table)
	mustExec(t, db, "ALTER TABLE "+table+"_drift RENAME TO "+table)
}

// testRunStateList renders the comma-separated quoted state list used inside
// the test_run state CHECK expression.
func testRunStateList(states []string) string {
	quoted := make([]string, len(states))
	for i, state := range states {
		quoted[i] = "'" + state + "'"
	}

	return strings.Join(quoted, ", ")
}

// testRunDDLWithStates renders the full test_run definition as the drift
// table with the state CHECK list built from states, so CHECK drift tests
// change only the state list and keep every column identical to the contract.
func testRunDDLWithStates(states []string) string {
	return testRunDDLWithStateCheck("state IN (" + testRunStateList(states) + ")")
}

// testRunDDLWithStateCheck renders the full test_run definition as the drift
// table with check spliced in as the literal state CHECK body, so CHECK drift
// tests can store broadened expressions (OR tails, extra comparisons, comment
// tricks) while keeping every column identical to the contract.
func testRunDDLWithStateCheck(check string) string {
	return testRunDDLWithStateColumn("state TEXT NOT NULL CHECK (" + check + ")")
}

// testRunDDLWithStateColumn renders the full test_run definition as the drift
// table with stateColumn spliced in as the complete state column definition,
// so drift tests can place text around the column (leading comments) or add
// column clauses (COLLATE) while keeping every other column identical to the
// contract.
func testRunDDLWithStateColumn(stateColumn string) string {
	return fmt.Sprintf(`CREATE TABLE %s (
		test_run_id TEXT PRIMARY KEY,
		is_active INTEGER NOT NULL,
		%s,
		target_origin TEXT NOT NULL,
		target_host TEXT NOT NULL,
		discovery_url TEXT NOT NULL,
		jwks_uri TEXT NOT NULL,
		terminal_reason TEXT,
		finished_at INTEGER,
		overall_grade TEXT,
		manifest_schema TEXT NOT NULL,
		manifest_json TEXT,
		session_kind TEXT NOT NULL,
		bob_user_id TEXT,
		reverse_invite_token TEXT,
		reverse_invite_imported_at INTEGER,
		designated_share_with TEXT,
		reverse_share_provider_id TEXT,
		stats_written_at INTEGER,
		opt_in_stats INTEGER NOT NULL DEFAULT 0,
		opt_in_permanent INTEGER NOT NULL DEFAULT 0,
		opt_in_stats_channel TEXT,
		opt_in_stats_at INTEGER,
		opt_in_permanent_channel TEXT,
		opt_in_permanent_at INTEGER,
		retention_tier TEXT,
		retention_locked_at INTEGER,
		expires_at INTEGER,
		permanent_report_id TEXT UNIQUE,
		harvested_at INTEGER,
		harvested_session_artifacts_at INTEGER,
		harvest_reason TEXT,
		created_at INTEGER NOT NULL,
		updated_at INTEGER NOT NULL
	)`, tableTestRun+"_drift", stateColumn)
}

// rebuildTestRun replaces the test_run definition like rebuildTable and then
// recreates the test_run indexes the drop removes, so drift cases keep the
// index contract intact and validation can only fail on the drifted aspect.
func rebuildTestRun(t *testing.T, db *gorm.DB, driftDDL string) {
	t.Helper()

	rebuildTable(t, db, tableTestRun, driftDDL)

	for _, stmt := range []string{
		`CREATE UNIQUE INDEX idx_test_run_one_active ON test_run (is_active) WHERE is_active = 1`,
		`CREATE INDEX idx_test_run_state ON test_run (state)`,
		`CREATE INDEX idx_test_run_session_kind ON test_run (session_kind)`,
		`CREATE INDEX idx_test_run_bob_user_id ON test_run (bob_user_id)`,
		`CREATE INDEX idx_test_run_expires_at ON test_run (expires_at)`,
		`CREATE INDEX idx_test_run_stats_heal ON test_run (stats_written_at) WHERE opt_in_stats = 1 AND stats_written_at IS NULL`,
	} {
		mustExec(t, db, stmt)
	}
}

// statsRawDDL renders the stats_raw definition under name; uniqueK controls
// the inline UNIQUE on k and extraFK adds a host_hash reference to
// stats_aggregate.
func statsRawDDL(name string, uniqueK, extraFK bool) string {
	kColumn := "k TEXT NOT NULL"
	if uniqueK {
		kColumn = "k TEXT NOT NULL UNIQUE"
	}

	hostColumn := "host_hash TEXT NOT NULL"
	if extraFK {
		hostColumn = "host_hash TEXT NOT NULL REFERENCES stats_aggregate (host_hash)"
	}

	return fmt.Sprintf(`CREATE TABLE %s (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		%s,
		%s,
		session_kind TEXT NOT NULL,
		reverse_invite_exercised INTEGER NOT NULL,
		platform TEXT NOT NULL,
		api_version TEXT NOT NULL,
		grade_discovery TEXT,
		grade_tls TEXT,
		grade_jwks TEXT,
		grade_httpsig TEXT,
		grade_sharing TEXT,
		grade_notification TEXT,
		grade_token TEXT,
		grade_capability TEXT,
		created_at INTEGER NOT NULL,
		window_bucket INTEGER
	)`, name, kColumn, hostColumn)
}
