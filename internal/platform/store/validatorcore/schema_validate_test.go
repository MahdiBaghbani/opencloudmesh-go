// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"errors"
	"strings"
	"testing"

	store "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
)

// TestAttach_VersionOneShapeDriftFailsClosed proves validation catches every
// contract aspect: each subtest applies the valid schema, mutates exactly one
// aspect, and requires Attach to fail closed with the drift attributed.
func TestAttach_VersionOneShapeDriftFailsClosed(t *testing.T) {
	t.Parallel()

	for _, drift := range versionOneShapeDrifts {
		t.Run(drift.name, func(t *testing.T) {
			t.Parallel()

			db := attachFresh(t)
			seedFoundV1NoTouchRows(t, db)
			drift.mutate(t, db)
			before := snapshotFoundV1NoTouch(t, db)

			if _, err := Attach(db, DefaultSessionConfig()); err == nil {
				t.Fatalf("Attach must fail closed on drift %q", drift.name)
			} else if !strings.Contains(err.Error(), drift.wantErr) {
				t.Fatalf("error = %v, want substring %q", err, drift.wantErr)
			}

			assertFoundV1NoTouch(t, db, before)
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
		tableShareCorrelation, tableReportExchange,
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

// TestAttach_ValidatorSchemaCardinalityFailsClosed covers a malformed
// validator_schema with more than one row. Multiple rows are a cardinality
// failure, not an unsupported-version failure and not empty-table recovery:
// the error taxonomy must stay distinct, validation must fail closed, and
// peer data must survive. An empty table is recovery, not this path.
func TestAttach_ValidatorSchemaCardinalityFailsClosed(t *testing.T) {
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

	mustExec(t, db, "INSERT INTO validator_schema (version) VALUES (2)")

	_, err := Attach(db, DefaultSessionConfig())
	if err == nil {
		t.Fatal("Attach must fail closed when validator_schema holds multiple rows")
	}

	if errors.Is(err, ErrUnsupportedValidatorSchemaVersion) {
		t.Fatalf("cardinality failure must not masquerade as unsupported version: %v", err)
	}

	if !strings.Contains(err.Error(), "validator_schema holds 2 rows, want exactly 1") {
		t.Fatalf("error = %v, want multiple-row cardinality failure", err)
	}

	var rowCount int64

	mustQueryCount(t, db, "SELECT COUNT(*) FROM validator_schema", &rowCount)

	if rowCount != 2 {
		t.Fatalf("validator_schema rows = %d, want 2 (no repair)", rowCount)
	}

	var peerCount int64

	mustQueryCount(t, db, "SELECT COUNT(*) FROM outgoing_shares WHERE share_id = 'share-card'", &peerCount)

	if peerCount != 1 {
		t.Fatalf("peer rows = %d, want 1 (peer data must survive)", peerCount)
	}
}
