// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"errors"
	"fmt"
	"strings"
	"testing"
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
		t.Fatalf("CHECK probe leaked %d test_run rows, want 0", count)
	}

	var evidenceCount int64

	mustQueryCount(t, db, "SELECT COUNT(*) FROM evidence_row", &evidenceCount)

	if evidenceCount != 0 {
		t.Fatalf("CHECK probe leaked %d evidence_row rows, want 0", evidenceCount)
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
