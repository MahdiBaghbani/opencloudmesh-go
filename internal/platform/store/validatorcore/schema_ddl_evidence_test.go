// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"strings"
	"testing"

	"gorm.io/gorm"
)

func TestEvidenceRow_ColumnsAndFK(t *testing.T) {
	t.Parallel()

	db := attachFresh(t)
	info := tableInfo(t, db, "evidence_row")

	if info["id"].PK != 1 {
		t.Fatal("evidence_row.id must be the primary key")
	}

	for _, col := range []string{"test_run_id", "area", "step", "reason_code", "severity", "affects_grade"} {
		if !info[col].NotNull {
			t.Fatalf("evidence_row.%s must be NOT NULL", col)
		}
	}

	if info["payload_redacted"].NotNull || info["exchange_id"].NotNull {
		t.Fatal("payload_redacted and exchange_id must be nullable")
	}

	var uniqueSQL string

	if err := db.Raw(
		"SELECT sql FROM sqlite_master WHERE type = 'index' AND name = 'idx_evidence_row'",
	).Scan(&uniqueSQL).Error; err != nil {
		t.Fatalf("read idx_evidence_row: %v", err)
	}

	if uniqueSQL == "" || !strings.Contains(strings.ToUpper(uniqueSQL), "UNIQUE") {
		t.Fatalf("idx_evidence_row must be a unique index: %q", uniqueSQL)
	}

	fks := foreignKeys(t, db, "evidence_row")
	runFK := findFK(fks, "test_run_id")

	if runFK == nil || runFK.Table != "test_run" || runFK.OnDelete != "RESTRICT" {
		t.Fatalf("evidence_row test_run FK = %+v, want test_run RESTRICT", runFK)
	}

	exFK := findFK(fks, "exchange_id")

	if exFK == nil || exFK.Table != "report_exchange" || exFK.OnDelete != "SET NULL" {
		t.Fatalf("evidence_row exchange FK = %+v, want report_exchange SET NULL", exFK)
	}
}

func insertEvidenceRow(t *testing.T, db *gorm.DB, step string) error {
	t.Helper()

	return db.Exec(`INSERT INTO evidence_row
		(test_run_id, area, step, reason_code, severity, affects_grade, exchange_id, created_at)
		VALUES ('run-ev', 'http', ?, 'timeout', 'important', TRUE, 1, 1)`, step).Error
}

func TestEvidenceRow_Constraints(t *testing.T) {
	t.Parallel()

	db := attachFresh(t)
	createTestRun(t, db, "run-ev")
	mustExec(t, db, `INSERT INTO report_exchange
		(test_run_id, seq, captured_at, direction, actor, endpoint_id, method, url, created_at)
		VALUES ('run-ev', 1, 1, 'out', 'validator', 'discovery', 'GET', 'https://t.example/x', 1)`)

	if err := insertEvidenceRow(t, db, "request"); err != nil {
		t.Fatalf("insert evidence: %v", err)
	}

	if err := insertEvidenceRow(t, db, "request"); err == nil {
		t.Fatal("duplicate (test_run_id, area, step, reason_code) must be rejected")
	}

	if err := insertEvidenceRow(t, db, "response"); err != nil {
		t.Fatalf("insert second evidence: %v", err)
	}

	mustExec(t, db, "DELETE FROM report_exchange WHERE exchange_id = 1")

	var nullCount int64

	mustQueryCount(t, db,
		"SELECT COUNT(*) FROM evidence_row WHERE test_run_id = 'run-ev' AND exchange_id IS NULL",
		&nullCount)

	if nullCount != 2 {
		t.Fatalf("exchange delete must SET NULL on evidence rows, got %d nulled", nullCount)
	}

	// Validator-owned child rows restrict test_run delete: the parent delete
	// must fail while evidence rows remain, then succeed once they are gone.
	if err := db.Exec("DELETE FROM test_run WHERE test_run_id = 'run-ev'").Error; err == nil {
		t.Fatal("test_run delete must be rejected while evidence rows remain")
	}

	mustExec(t, db, "DELETE FROM evidence_row WHERE test_run_id = 'run-ev'")
	mustExec(t, db, "DELETE FROM test_run WHERE test_run_id = 'run-ev'")

	var runCount int64

	mustQueryCount(t, db, "SELECT COUNT(*) FROM test_run WHERE test_run_id = 'run-ev'", &runCount)

	if runCount != 0 {
		t.Fatalf("test_run delete after child cleanup must remove the run, %d remain", runCount)
	}
}
