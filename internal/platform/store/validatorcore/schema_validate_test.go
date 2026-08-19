// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

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
