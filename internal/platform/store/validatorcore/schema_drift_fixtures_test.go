// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"testing"

	"gorm.io/gorm"
)

// shapeDrift is one version-1 schema drift case: mutate applies exactly one
// contract violation to an otherwise valid schema, and wantErr is the error
// substring attributing the failure to that aspect.
type shapeDrift struct {
	name    string
	mutate  func(t *testing.T, db *gorm.DB)
	wantErr string
}

// versionOneShapeDrifts is the fail-closed drift matrix: each case applies
// the valid schema, mutates exactly one contract aspect, and requires Attach
// to fail closed with the drift attributed.
var versionOneShapeDrifts = []shapeDrift{
	{
		name: "missing table",
		mutate: func(t *testing.T, db *gorm.DB) {
			t.Helper()
			mustExec(t, db, "DROP TABLE evidence_row")
		},
		wantErr: "table evidence_row is missing",
	},
	{
		name: "extra column",
		mutate: func(t *testing.T, db *gorm.DB) {
			t.Helper()
			mustExec(t, db, "ALTER TABLE stats_aggregate ADD COLUMN drift_extra TEXT")
		},
		wantErr: "stats_aggregate has 8 columns, want 7",
	},
	{
		name: "dropped column",
		mutate: func(t *testing.T, db *gorm.DB) {
			t.Helper()
			// terminal_reason carries no index or FK, so DROP COLUMN succeeds.
			mustExec(t, db, "ALTER TABLE test_run DROP COLUMN terminal_reason")
		},
		wantErr: "test_run has 33 columns, want 34",
	},
	{
		name: "renamed column",
		mutate: func(t *testing.T, db *gorm.DB) {
			t.Helper()
			mustExec(t, db, "ALTER TABLE test_run RENAME COLUMN terminal_reason TO terminal_why")
		},
		wantErr: "test_run column 7 is terminal_why, want terminal_reason",
	},
	{
		name: "wrong column type",
		mutate: func(t *testing.T, db *gorm.DB) {
			t.Helper()
			rebuildTable(t, db, tableStatsAggregate, `CREATE TABLE stats_aggregate_drift (
					host_hash TEXT PRIMARY KEY,
					total_sessions TEXT NOT NULL,
					healthy_sessions INTEGER NOT NULL,
					last_platform TEXT NOT NULL,
					last_healthy INTEGER NOT NULL,
					first_seen_ts INTEGER NOT NULL,
					last_seen_ts INTEGER NOT NULL
				)`)
		},
		wantErr: "stats_aggregate.total_sessions type = TEXT, want INTEGER",
	},
	{
		name: "wrong nullability",
		mutate: func(t *testing.T, db *gorm.DB) {
			t.Helper()
			rebuildTable(t, db, tableStatsAggregate, `CREATE TABLE stats_aggregate_drift (
					host_hash TEXT PRIMARY KEY,
					total_sessions INTEGER NOT NULL,
					healthy_sessions INTEGER NOT NULL,
					last_platform TEXT,
					last_healthy INTEGER NOT NULL,
					first_seen_ts INTEGER NOT NULL,
					last_seen_ts INTEGER NOT NULL
				)`)
		},
		wantErr: "stats_aggregate.last_platform NOT NULL = false, want true",
	},
	{
		name: "wrong default",
		mutate: func(t *testing.T, db *gorm.DB) {
			t.Helper()
			rebuildTable(t, db, tableShareCorrelation, `CREATE TABLE share_correlation_drift (
					id INTEGER PRIMARY KEY AUTOINCREMENT,
					test_run_id TEXT NOT NULL REFERENCES test_run (test_run_id) ON UPDATE CASCADE ON DELETE RESTRICT,
					role TEXT NOT NULL,
					sender_host TEXT NOT NULL,
					provider_id TEXT NOT NULL,
					local_identity TEXT NOT NULL,
					share_id TEXT,
					invite_id TEXT,
					status TEXT NOT NULL DEFAULT 'pending',
					created_at INTEGER NOT NULL
				)`)
		},
		wantErr: "share_correlation.status default = 'pending', want 'confirmed'",
	},
	{
		name: "wrong primary key",
		mutate: func(t *testing.T, db *gorm.DB) {
			t.Helper()
			rebuildTable(t, db, tableStatsAggregate, `CREATE TABLE stats_aggregate_drift (
					host_hash TEXT,
					total_sessions INTEGER NOT NULL,
					healthy_sessions INTEGER NOT NULL,
					last_platform TEXT NOT NULL,
					last_healthy INTEGER NOT NULL,
					first_seen_ts INTEGER NOT NULL,
					last_seen_ts INTEGER NOT NULL
				)`)
		},
		wantErr: "stats_aggregate.host_hash primary key position = 0, want 1",
	},
	{
		name: "missing named index",
		mutate: func(t *testing.T, db *gorm.DB) {
			t.Helper()
			mustExec(t, db, "DROP INDEX idx_stats_agg_last_seen")
		},
		wantErr: "index idx_stats_agg_last_seen is missing",
	},
	{
		name: "wrong index columns",
		mutate: func(t *testing.T, db *gorm.DB) {
			t.Helper()
			mustExec(t, db, "DROP INDEX idx_report_ex_run_seq")
			mustExec(t, db, "CREATE UNIQUE INDEX idx_report_ex_run_seq ON report_exchange (test_run_id)")
		},
		wantErr: "index idx_report_ex_run_seq columns = [test_run_id], want [test_run_id seq]",
	},
	{
		name: "wrong index uniqueness",
		mutate: func(t *testing.T, db *gorm.DB) {
			t.Helper()
			mustExec(t, db, "DROP INDEX idx_test_run_state")
			mustExec(t, db, "CREATE UNIQUE INDEX idx_test_run_state ON test_run (state)")
		},
		wantErr: "index idx_test_run_state unique = true, want false",
	},
	{
		name: "missing partial predicate",
		mutate: func(t *testing.T, db *gorm.DB) {
			t.Helper()
			mustExec(t, db, "DROP INDEX idx_test_run_one_active")
			mustExec(t, db, "CREATE UNIQUE INDEX idx_test_run_one_active ON test_run (is_active)")
		},
		wantErr: "index idx_test_run_one_active partial = false, want true",
	},
	{
		name: "wrong partial predicate",
		mutate: func(t *testing.T, db *gorm.DB) {
			t.Helper()
			mustExec(t, db, "DROP INDEX idx_test_run_stats_heal")
			mustExec(t, db,
				"CREATE INDEX idx_test_run_stats_heal ON test_run (stats_written_at) WHERE stats_written_at IS NULL")
		},
		wantErr: "index idx_test_run_stats_heal predicate",
	},
	{
		name: "missing inline unique",
		mutate: func(t *testing.T, db *gorm.DB) {
			t.Helper()
			rebuildTable(t, db, tableStatsRaw, statsRawDDL("stats_raw_drift", false, false))
		},
		wantErr: "stats_raw.k must be UNIQUE",
	},
	{
		name: "wrong foreign key action",
		mutate: func(t *testing.T, db *gorm.DB) {
			t.Helper()
			rebuildTable(t, db, tableEvidenceRow, `CREATE TABLE evidence_row_drift (
					id INTEGER PRIMARY KEY AUTOINCREMENT,
					test_run_id TEXT NOT NULL REFERENCES test_run (test_run_id) ON DELETE RESTRICT,
					area TEXT NOT NULL,
					step TEXT NOT NULL,
					reason_code TEXT NOT NULL,
					severity TEXT NOT NULL,
					affects_grade INTEGER NOT NULL,
					payload_redacted TEXT,
					exchange_id INTEGER REFERENCES report_exchange (exchange_id) ON DELETE NO ACTION,
					created_at INTEGER NOT NULL
				)`)
		},
		wantErr: "evidence_row.exchange_id FK",
	},
	{
		name: "missing foreign key",
		mutate: func(t *testing.T, db *gorm.DB) {
			t.Helper()
			rebuildTable(t, db, tableDispatchReservation, `CREATE TABLE dispatch_reservation_drift (
					test_run_id TEXT PRIMARY KEY,
					provider_id TEXT NOT NULL UNIQUE,
					webdav_id TEXT NOT NULL UNIQUE,
					shared_secret TEXT NOT NULL,
					receiver_host TEXT NOT NULL,
					share_with TEXT NOT NULL,
					probe_file_path TEXT NOT NULL,
					status TEXT NOT NULL,
					outgoing_share_id TEXT,
					remote_sent_at INTEGER,
					cas_committed_at INTEGER,
					created_at INTEGER NOT NULL,
					updated_at INTEGER
				)`)
		},
		wantErr: "dispatch_reservation has 0 foreign keys, want 1",
	},
	{
		name: "extra foreign key",
		mutate: func(t *testing.T, db *gorm.DB) {
			t.Helper()
			rebuildTable(t, db, tableStatsRaw, statsRawDDL("stats_raw_drift", true, true))
		},
		wantErr: "stats_raw has 1 foreign keys, want 0",
	},
	{
		name: "dormant state admitted by check",
		mutate: func(t *testing.T, db *gorm.DB) {
			t.Helper()

			states := append([]string{}, testRunStates...)
			states = append(states, "passive_done")

			rebuildTable(t, db, tableTestRun, testRunDDLWithStates(states))
		},
		wantErr: `test_run state CHECK admits dormant state "passive_done"`,
	},
	{
		name: "required live state rejected by check",
		mutate: func(t *testing.T, db *gorm.DB) {
			t.Helper()

			var states []string

			for _, state := range testRunStates {
				if state != StateInterrupted {
					states = append(states, state)
				}
			}

			rebuildTable(t, db, tableTestRun, testRunDDLWithStates(states))
		},
		wantErr: `test_run state CHECK rejects required state "interrupted"`,
	},
	{
		name: "unexpected state admitted by check",
		mutate: func(t *testing.T, db *gorm.DB) {
			t.Helper()

			states := append([]string{}, testRunStates...)
			states = append(states, "terminal_unknown")

			rebuildTable(t, db, tableTestRun, testRunDDLWithStates(states))
		},
		wantErr: `test_run state CHECK admits unexpected state "terminal_unknown"`,
	},
	{
		name: "renamed live state rejected by check",
		mutate: func(t *testing.T, db *gorm.DB) {
			t.Helper()

			states := make([]string, 0, len(testRunStates))

			for _, state := range testRunStates {
				if state == StateInterrupted {
					states = append(states, "interrupted_legacy")
				} else {
					states = append(states, state)
				}
			}

			rebuildTable(t, db, tableTestRun, testRunDDLWithStates(states))
		},
		wantErr: `test_run state CHECK rejects required state "interrupted"`,
	},
	{
		name: "state check OR tautology tail",
		mutate: func(t *testing.T, db *gorm.DB) {
			t.Helper()

			check := "state IN (" + testRunStateList(testRunStates) + ") OR 1=1"
			rebuildTable(t, db, tableTestRun, testRunDDLWithStateCheck(check))
		},
		wantErr: `test_run state CHECK admits unexpected state ""`,
	},
	{
		name: "state check OR dormant state tail",
		mutate: func(t *testing.T, db *gorm.DB) {
			t.Helper()

			check := "state IN (" + testRunStateList(testRunStates) + ") OR state = 'passive_done'"
			rebuildTable(t, db, tableTestRun, testRunDDLWithStateCheck(check))
		},
		wantErr: `test_run state CHECK admits dormant state "passive_done"`,
	},
	{
		name: "state check excludes a live state via AND tail",
		mutate: func(t *testing.T, db *gorm.DB) {
			t.Helper()

			check := "state IN (" + testRunStateList(testRunStates) + ") AND state <> 'created'"
			rebuildTable(t, db, tableTestRun, testRunDDLWithStateCheck(check))
		},
		wantErr: `test_run state CHECK rejects required state "created"`,
	},
	{
		name: "state collation nocase",
		mutate: func(t *testing.T, db *gorm.DB) {
			t.Helper()

			rebuildTestRun(t, db, testRunDDLWithStateColumn(
				"state TEXT NOT NULL COLLATE NOCASE CHECK (state IN ("+testRunStateList(testRunStates)+"))"))
		},
		wantErr: "test_run.state matches case-insensitively",
	},
	{
		name: "state collation rtrim",
		mutate: func(t *testing.T, db *gorm.DB) {
			t.Helper()

			rebuildTestRun(t, db, testRunDDLWithStateColumn(
				"state TEXT NOT NULL COLLATE RTRIM CHECK (state IN ("+testRunStateList(testRunStates)+"))"))
		},
		wantErr: "test_run.state ignores trailing spaces",
	},
	{
		name: "state collation after check",
		mutate: func(t *testing.T, db *gorm.DB) {
			t.Helper()

			rebuildTestRun(t, db, testRunDDLWithStateColumn(
				"state TEXT NOT NULL CHECK (state IN ("+testRunStateList(testRunStates)+")) collate nocase"))
		},
		wantErr: "test_run.state matches case-insensitively",
	},
	{
		name: "unexpected named index",
		mutate: func(t *testing.T, db *gorm.DB) {
			t.Helper()
			mustExec(t, db, "CREATE INDEX idx_stats_raw_drift ON stats_raw (platform)")
		},
		wantErr: "stats_raw carries unexpected index idx_stats_raw_drift",
	},
	{
		name: "duplicate foreign key",
		mutate: func(t *testing.T, db *gorm.DB) {
			t.Helper()
			rebuildTable(t, db, tableShareCorrelation, `CREATE TABLE share_correlation_drift (
					id INTEGER PRIMARY KEY AUTOINCREMENT,
					test_run_id TEXT NOT NULL REFERENCES test_run (test_run_id) ON UPDATE CASCADE ON DELETE RESTRICT,
					role TEXT NOT NULL,
					sender_host TEXT NOT NULL,
					provider_id TEXT NOT NULL,
					local_identity TEXT NOT NULL,
					share_id TEXT,
					invite_id TEXT,
					status TEXT NOT NULL DEFAULT 'confirmed',
					created_at INTEGER NOT NULL,
					FOREIGN KEY (test_run_id) REFERENCES test_run (test_run_id) ON UPDATE CASCADE ON DELETE RESTRICT
				)`)
		},
		wantErr: "share_correlation.test_run_id has duplicate foreign keys",
	},
	{
		name: "unexpected trigger on test_run",
		mutate: func(t *testing.T, db *gorm.DB) {
			t.Helper()
			mustExec(t, db, "CREATE TRIGGER trg_test_run_drift AFTER UPDATE ON test_run BEGIN SELECT 1; END")
		},
		wantErr: "test_run carries unexpected trigger trg_test_run_drift",
	},
}
