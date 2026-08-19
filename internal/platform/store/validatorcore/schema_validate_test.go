// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// ocmgo:file-length-ignore: schema drift, rollback, and cardinality fail-closed coverage

package validatorcore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"

	"gorm.io/gorm"

	store "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
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
					test_run_id TEXT NOT NULL REFERENCES test_run (test_run_id) ON UPDATE CASCADE ON DELETE CASCADE,
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
					test_run_id TEXT NOT NULL REFERENCES test_run (test_run_id) ON DELETE CASCADE,
					area TEXT NOT NULL,
					step TEXT NOT NULL,
					reason_code TEXT NOT NULL,
					severity TEXT NOT NULL,
					affects_grade INTEGER NOT NULL,
					payload_redacted TEXT,
					exchange_id INTEGER REFERENCES report_exchange (exchange_id) ON DELETE CASCADE,
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
					test_run_id TEXT NOT NULL REFERENCES test_run (test_run_id) ON UPDATE CASCADE ON DELETE CASCADE,
					role TEXT NOT NULL,
					sender_host TEXT NOT NULL,
					provider_id TEXT NOT NULL,
					local_identity TEXT NOT NULL,
					share_id TEXT,
					invite_id TEXT,
					status TEXT NOT NULL DEFAULT 'confirmed',
					created_at INTEGER NOT NULL,
					FOREIGN KEY (test_run_id) REFERENCES test_run (test_run_id) ON UPDATE CASCADE ON DELETE CASCADE
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

// TestAttach_StateCheckProbeLeavesNoRows proves the behavioral state CHECK
// probe is transaction-neutral: re-attaching over the canonical schema runs
// the validation path (which inserts and rolls back probe rows) and must still
// succeed while leaving test_run empty, so no probe row escapes the savepoint.
func TestAttach_StateCheckProbeLeavesNoRows(t *testing.T) {
	t.Parallel()

	db := attachFresh(t)

	if _, err := Attach(db, DefaultSessionConfig()); err != nil {
		t.Fatalf("re-attach must validate the canonical schema: %v", err)
	}

	var count int64

	mustQueryCount(t, db, "SELECT COUNT(*) FROM test_run", &count)

	if count != 0 {
		t.Fatalf("state CHECK probe leaked %d test_run rows, want 0", count)
	}
}

// TestAttach_StateProbeNonCheckErrorFailsClosed proves the behavioral state
// probe classifies failures rather than treating every insert error as a
// rejection. A BEFORE INSERT trigger that aborts makes the first probe insert
// fail for a reason other than the state CHECK, so Attach must fail closed with
// an honest probe-infrastructure error and must not misreport it as a rejected
// required state.
func TestAttach_StateProbeNonCheckErrorFailsClosed(t *testing.T) {
	t.Parallel()

	db := attachFresh(t)
	mustExec(t, db,
		"CREATE TRIGGER trg_test_run_probe_abort BEFORE INSERT ON test_run BEGIN SELECT RAISE(ABORT, 'probe boom'); END")

	_, err := Attach(db, DefaultSessionConfig())
	if err == nil {
		t.Fatal("Attach must fail closed when a state probe insert fails for a non-CHECK reason")
	}

	if !strings.Contains(err.Error(), "state probe failed") {
		t.Fatalf("error = %v, want a probe-infrastructure failure", err)
	}

	if strings.Contains(err.Error(), "rejects required state") {
		t.Fatalf("error = %v, must not misclassify an infrastructure failure as a state rejection", err)
	}
}

// TestIsStateCheckRejection proves the probe error classifier only treats a
// genuine, typed SQLite CHECK-constraint failure as a state rejection. The
// positive case runs a real CHECK-violating insert so it exercises the driver's
// typed extended result code (275) by construction; if the typed handling
// regresses it fails. Primary key, NOT NULL, plain non-driver errors, and a
// spoofed non-driver error whose text contains "CHECK constraint failed" are
// all classified as not rejections and must fail closed as infrastructure
// errors instead, proving the classifier never trusts the message text.
func TestIsStateCheckRejection(t *testing.T) {
	t.Parallel()

	gdb := openSchemaTestDB(t)

	sqlDB, err := gdb.DB()
	if err != nil {
		t.Fatalf("sql handle: %v", err)
	}

	mustExecSQL(t, sqlDB, `CREATE TABLE probe_classify (
		id TEXT PRIMARY KEY,
		label TEXT NOT NULL,
		bounded INTEGER NOT NULL CHECK (bounded IN (0, 1))
	)`)
	mustExecSQL(t, sqlDB, "INSERT INTO probe_classify (id, label, bounded) VALUES ('seed', 'seed', 1)")

	cases := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "typed check constraint failure",
			err:  insertErrSQL(t, sqlDB, "INSERT INTO probe_classify (id, label, bounded) VALUES ('c', 'x', 2)"),
			want: true,
		},
		{
			name: "primary key collision",
			err:  insertErrSQL(t, sqlDB, "INSERT INTO probe_classify (id, label, bounded) VALUES ('seed', 'x', 1)"),
			want: false,
		},
		{
			name: "not null violation",
			err:  insertErrSQL(t, sqlDB, "INSERT INTO probe_classify (id, label, bounded) VALUES ('nn', NULL, 1)"),
			want: false,
		},
		{
			name: "non-sqlite error",
			err:  errors.New("dial tcp: connection refused"),
			want: false,
		},
		{
			name: "spoofed check message on non-driver error",
			err:  fmt.Errorf("probe classify insert: %w", errors.New("CHECK constraint failed: fake")),
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := isStateCheckRejection(tc.err); got != tc.want {
				t.Fatalf("isStateCheckRejection(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// mustExecSQL runs query on the raw *sql.DB and fails the test on error.
func mustExecSQL(t *testing.T, sqlDB *sql.DB, query string) {
	t.Helper()

	if _, err := sqlDB.ExecContext(context.Background(), query); err != nil {
		t.Fatalf("exec: %v\n%s", err, query)
	}
}

// insertErrSQL runs an insert that must fail and returns the real typed driver
// error wrapped once with %w, so classifier tests exercise the same errors.As
// unwrapping to *gosqlite.Error and Code() == 275 (SQLITE_CONSTRAINT_CHECK)
// that the probe relies on when it inspects a real driver error.
func insertErrSQL(t *testing.T, sqlDB *sql.DB, query string) error {
	t.Helper()

	_, err := sqlDB.ExecContext(context.Background(), query)
	if err == nil {
		t.Fatalf("insert must fail: %s", query)
	}

	return fmt.Errorf("probe classify insert: %w", err)
}

// TestAttach_VersionOneShapeDriftFailsClosed proves validation catches every
// contract aspect: each subtest applies the valid schema, mutates exactly one
// aspect, and requires Attach to fail closed with the drift attributed.
func TestAttach_VersionOneShapeDriftFailsClosed(t *testing.T) {
	t.Parallel()

	for _, drift := range versionOneShapeDrifts {
		t.Run(drift.name, func(t *testing.T) {
			t.Parallel()

			db := attachFresh(t)
			drift.mutate(t, db)

			if _, err := Attach(db, DefaultSessionConfig()); err == nil {
				t.Fatalf("Attach must fail closed on drift %q", drift.name)
			} else if !strings.Contains(err.Error(), drift.wantErr) {
				t.Fatalf("error = %v, want substring %q", err, drift.wantErr)
			}
		})
	}
}

// TestAttach_TestRunStateCollationAccepted proves the test_run state
// collation check accepts the shapes the canonical schema allows on a live
// database: no COLLATE clause (the SQLite default BINARY) and an explicit
// COLLATE BINARY.
func TestAttach_TestRunStateCollationAccepted(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		stateColumn string
	}{
		{
			name:        "default collation",
			stateColumn: "state TEXT NOT NULL CHECK (state IN (" + testRunStateList(testRunStates) + "))",
		},
		{
			name:        "explicit binary collation",
			stateColumn: "state TEXT NOT NULL COLLATE BINARY CHECK (state IN (" + testRunStateList(testRunStates) + "))",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			db := attachFresh(t)
			rebuildTestRun(t, db, testRunDDLWithStateColumn(tc.stateColumn))

			if _, err := Attach(db, DefaultSessionConfig()); err != nil {
				t.Fatalf("Attach must accept test_run.state with %s: %v", tc.name, err)
			}
		})
	}
}

// TestApplyValidatorSchema_MidDDLFailureRollsBack forces a deterministic
// failure in the middle of the explicit DDL sequence and proves the whole
// transaction rolls back: no half-created validator tables, no validator_schema
// row, and the legacy tables recovery would have dropped survive with rows.
func TestApplyValidatorSchema_MidDDLFailureRollsBack(t *testing.T) {
	t.Parallel()

	sqlCore := openPeerStore(t)
	db := sqlCore.DB()

	// Legacy-shaped validator tables with marker rows. Recovery drops these
	// inside the same transaction, so a mid-DDL failure must restore them.
	mustExec(t, db, "CREATE TABLE test_run (test_run_id TEXT PRIMARY KEY, marker TEXT)")
	mustExec(t, db, "INSERT INTO test_run (test_run_id, marker) VALUES ('legacy-run', 'keep')")
	mustExec(t, db, "CREATE TABLE stats_raw (id INTEGER PRIMARY KEY, marker TEXT)")
	mustExec(t, db, "INSERT INTO stats_raw (id, marker) VALUES (1, 'keep')")

	// Deterministic failure mechanism: occupy the idx_report_ex_run_seq name
	// with a plain table. Table and index names share one SQLite schema
	// namespace, so the mid-sequence CREATE UNIQUE INDEX statement fails.
	mustExec(t, db, "CREATE TABLE idx_report_ex_run_seq (id INTEGER)")

	err := ApplyValidatorSchema(db)
	if err == nil {
		t.Fatal("ApplyValidatorSchema must fail on the mid-DDL name collision")
	}

	if !strings.Contains(err.Error(), "apply statement") {
		t.Fatalf("error = %v, want the wrapped apply-statement failure", err)
	}

	// Tables the sequence creates only after the failure point, plus the
	// version table, must not exist at all.
	for _, table := range []string{
		tableShareCorrelation, tableStatsAggregate, tableReportExchange,
		tableEvidenceRow, tableDispatchReservation, tableValidatorSchema,
	} {
		if db.Migrator().HasTable(table) {
			t.Fatalf("table %s must not exist after rollback", table)
		}
	}

	// The legacy tables survive the rolled-back recovery with their rows.
	var runMarker string
	if err := db.Raw(
		"SELECT marker FROM test_run WHERE test_run_id = 'legacy-run'",
	).Scan(&runMarker).Error; err != nil {
		t.Fatalf("legacy test_run must survive rollback: %v", err)
	}

	if runMarker != "keep" {
		t.Fatalf("legacy test_run marker = %q, want keep (recovery rolled back)", runMarker)
	}

	var rawMarker string
	if err := db.Raw(
		"SELECT marker FROM stats_raw WHERE id = 1",
	).Scan(&rawMarker).Error; err != nil {
		t.Fatalf("legacy stats_raw must survive rollback: %v", err)
	}

	if rawMarker != "keep" {
		t.Fatalf("legacy stats_raw marker = %q, want keep (recovery rolled back)", rawMarker)
	}

	// The blocker table itself is untouched.
	if !db.Migrator().HasTable("idx_report_ex_run_seq") {
		t.Fatal("blocker table idx_report_ex_run_seq must survive the failed apply")
	}
}

// TestAttach_PeerTableTriggerAccepted proves the trigger inventory stays
// scoped to validator-owned tables: a trigger on a peer table is not drift
// and Attach still succeeds.
func TestAttach_PeerTableTriggerAccepted(t *testing.T) {
	t.Parallel()

	db := attachFresh(t)
	mustExec(t, db, "CREATE TRIGGER trg_peer_outgoing_shares AFTER INSERT ON outgoing_shares BEGIN SELECT 1; END")

	if _, err := Attach(db, DefaultSessionConfig()); err != nil {
		t.Fatalf("Attach must accept a peer-table trigger: %v", err)
	}
}

// TestAttach_ValidatorSchemaCardinalityFailsClosed covers malformed
// validator_schema row counts. Zero rows and multiple rows are cardinality
// failures, not unsupported-version failures: the error taxonomy must stay
// distinct, validation must fail closed, and peer data must survive.
func TestAttach_ValidatorSchemaCardinalityFailsClosed(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		corrupt  func(t *testing.T, db *gorm.DB)
		wantErr  string
		wantRows int64
	}{
		{
			name: "zero rows",
			corrupt: func(t *testing.T, db *gorm.DB) {
				t.Helper()
				mustExec(t, db, "DELETE FROM validator_schema")
			},
			wantErr:  "validator_schema holds 0 rows, want exactly 1",
			wantRows: 0,
		},
		{
			name: "multiple rows",
			corrupt: func(t *testing.T, db *gorm.DB) {
				t.Helper()
				mustExec(t, db, "INSERT INTO validator_schema (version) VALUES (2)")
			},
			wantErr:  "validator_schema holds 2 rows, want exactly 1",
			wantRows: 2,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sqlCore := openPeerStore(t)
			db := sqlCore.DB()

			peer := store.OutgoingShare{
				ShareID:    "share-card",
				ProviderID: "provider-card",
				WebDAVID:   "webdav-card",
				CreatedAt:  1,
			}

			if err := db.Create(&peer).Error; err != nil {
				t.Fatalf("seed peer row: %v", err)
			}

			if _, err := Attach(db, DefaultSessionConfig()); err != nil {
				t.Fatalf("initial Attach: %v", err)
			}

			tc.corrupt(t, db)

			_, err := Attach(db, DefaultSessionConfig())
			if err == nil {
				t.Fatalf("Attach must fail closed on validator_schema %s", tc.name)
			}

			if errors.Is(err, ErrUnsupportedValidatorSchemaVersion) {
				t.Fatalf("cardinality failure must not masquerade as unsupported version: %v", err)
			}

			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want substring %q", err, tc.wantErr)
			}

			// Fail closed without repair: the malformed row count remains.
			var rowCount int64

			mustQueryCount(t, db, "SELECT COUNT(*) FROM validator_schema", &rowCount)

			if rowCount != tc.wantRows {
				t.Fatalf("validator_schema rows = %d, want %d (no repair)", rowCount, tc.wantRows)
			}

			// Peer data survives the failed Attach.
			var peerCount int64

			mustQueryCount(t, db, "SELECT COUNT(*) FROM outgoing_shares WHERE share_id = 'share-card'", &peerCount)

			if peerCount != 1 {
				t.Fatalf("peer rows = %d, want 1 (peer data must survive)", peerCount)
			}
		})
	}
}
