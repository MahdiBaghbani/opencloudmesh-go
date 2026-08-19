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

var reportExchangeColumns = []string{
	"exchange_id", "test_run_id", "seq", "captured_at", "started_at", "ended_at",
	"duration_ms", "direction", "actor", "local_identity", "corr_role", "leg",
	"endpoint_id", "method", "url", "host", "status_code", "http_version",
	"error_text", "request_id", "req_headers_json", "resp_headers_json",
	"sig_raw", "sig_key_id", "sig_algorithm", "sig_scheme", "sig_valid",
	"digest", "req_body_redacted", "resp_body_redacted", "req_body_raw",
	"resp_body_raw", "req_body_sha256", "resp_body_sha256", "req_body_bytes",
	"resp_body_bytes", "req_body_truncated", "resp_body_truncated", "grade",
	"reason_codes", "created_at",
}

func TestReportExchange_ColumnsAndFK(t *testing.T) {
	t.Parallel()

	db := attachFresh(t)
	info := tableInfo(t, db, "report_exchange")

	if info["exchange_id"].PK != 1 {
		t.Fatal("exchange_id must be the primary key")
	}

	if _, ok := info["id"]; ok {
		t.Fatal("report_exchange must not have an id column")
	}

	if !info["test_run_id"].NotNull {
		t.Fatal("report_exchange.test_run_id must be NOT NULL")
	}

	if info["actor"].NotNull {
		t.Fatal("report_exchange.actor must be nullable")
	}

	if !info["endpoint_id"].NotNull {
		t.Fatal("report_exchange.endpoint_id must be NOT NULL")
	}

	for _, col := range reportExchangeColumns {
		if _, ok := info[col]; !ok {
			t.Fatalf("report_exchange missing column %s", col)
		}
	}

	fks := foreignKeys(t, db, "report_exchange")
	fk := findFK(fks, colTestRunID)

	if fk == nil {
		t.Fatal("report_exchange missing FK on test_run_id")
	}

	if fk.Table != "test_run" || fk.OnUpdate != "CASCADE" || fk.OnDelete != "RESTRICT" {
		t.Fatalf("report_exchange FK = %+v, want test_run CASCADE/RESTRICT", fk)
	}
}

func TestReportExchange_BodyColumnTypes(t *testing.T) {
	t.Parallel()

	db := attachFresh(t)
	info := tableInfo(t, db, "report_exchange")

	for _, col := range []string{"req_body_raw", "resp_body_raw"} {
		if !strings.EqualFold(info[col].Type, "BLOB") {
			t.Fatalf("report_exchange.%s must be BLOB, got %q", col, info[col].Type)
		}
	}

	for _, col := range []string{"req_body_truncated", "resp_body_truncated"} {
		if !info[col].NotNull || info[col].DfltValue == nil || *info[col].DfltValue != "0" {
			t.Fatalf("report_exchange.%s must be NOT NULL DEFAULT 0, got %+v", col, info[col])
		}
	}
}

func TestReportExchange_LockedIndexNames(t *testing.T) {
	t.Parallel()

	db := attachFresh(t)

	for _, index := range []string{
		"idx_report_ex_run_seq",
		"idx_report_ex_run_captured",
		"idx_report_ex_run_leg",
		"idx_report_ex_run_identity",
		"idx_report_ex_run_endpoint",
		"idx_report_ex_idem",
	} {
		var sqlText string

		if err := db.Raw(
			"SELECT sql FROM sqlite_master WHERE type = 'index' AND name = ?", index,
		).Scan(&sqlText).Error; err != nil {
			t.Fatalf("read index %s: %v", index, err)
		}

		if sqlText == "" {
			t.Fatalf("index %s missing", index)
		}
	}
}

func insertReportExchange(t *testing.T, db *gorm.DB, seq int, requestID *string) error {
	t.Helper()

	args := []any{"run-rex", seq, 1, "out", "validator", "discovery", "GET", "https://t.example/x", 1}
	reqExpr := "NULL"

	if requestID != nil {
		reqExpr = "?"

		args = append(args, *requestID)
	}

	return db.Exec(`INSERT INTO report_exchange
		(test_run_id, seq, captured_at, direction, actor, endpoint_id, method, url, created_at, request_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, `+reqExpr+`)`, args...).Error
}

func TestReportExchange_Constraints(t *testing.T) {
	t.Parallel()

	db := attachFresh(t)
	createTestRun(t, db, "run-rex")

	if err := insertReportExchange(t, db, 1, nil); err != nil {
		t.Fatalf("insert exchange: %v", err)
	}

	if err := insertReportExchange(t, db, 1, nil); err == nil {
		t.Fatal("duplicate (test_run_id, seq) must be rejected")
	}

	reqID := "req-1"

	if err := insertReportExchange(t, db, 2, &reqID); err != nil {
		t.Fatalf("insert exchange with request_id: %v", err)
	}

	if err := insertReportExchange(t, db, 3, &reqID); err == nil {
		t.Fatal("duplicate nonempty (test_run_id, direction, request_id) must be rejected")
	}

	empty := ""

	if err := insertReportExchange(t, db, 4, &empty); err != nil {
		t.Fatalf("insert exchange with empty request_id: %v", err)
	}

	if err := insertReportExchange(t, db, 5, &empty); err != nil {
		t.Fatal("empty request_id rows must not collide in the idempotency index")
	}

	if err := insertReportExchange(t, db, 6, nil); err != nil {
		t.Fatal("NULL request_id rows must not collide in the idempotency index")
	}

	// actor is nullable in the final contract.
	err := db.Exec(`INSERT INTO report_exchange
		(test_run_id, seq, captured_at, direction, actor, endpoint_id, method, url, created_at)
		VALUES ('run-rex', 7, 1, 'in', NULL, 'discovery', 'GET', 'https://t.example/y', 1)`).Error
	if err != nil {
		t.Fatalf("NULL actor must be accepted: %v", err)
	}

	// endpoint_id is NOT NULL in the final contract.
	err = db.Exec(`INSERT INTO report_exchange
		(test_run_id, seq, captured_at, direction, actor, method, url, created_at)
		VALUES ('run-rex', 8, 1, 'in', NULL, 'GET', 'https://t.example/z', 1)`).Error
	if err == nil {
		t.Fatal("omitting endpoint_id must be rejected")
	}
}
