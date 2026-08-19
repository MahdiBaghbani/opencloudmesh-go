// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"testing"

	"gorm.io/gorm"
)

func TestDispatchReservation_Schema(t *testing.T) {
	t.Parallel()

	db := attachFresh(t)
	info := tableInfo(t, db, "dispatch_reservation")

	if info["test_run_id"].PK != 1 {
		t.Fatal("dispatch_reservation.test_run_id must be the primary key")
	}

	for _, col := range []string{
		"provider_id", "webdav_id", "shared_secret", "receiver_host",
		"share_with", "probe_file_path", "status", "created_at",
	} {
		if !info[col].NotNull {
			t.Fatalf("dispatch_reservation.%s must be NOT NULL", col)
		}
	}

	for _, col := range []string{"outgoing_share_id", "remote_sent_at", "cas_committed_at", "updated_at"} {
		if info[col].NotNull {
			t.Fatalf("dispatch_reservation.%s must be nullable", col)
		}
	}

	fks := foreignKeys(t, db, "dispatch_reservation")
	fk := findFK(fks, "test_run_id")

	if fk == nil || fk.Table != "test_run" || fk.OnDelete != "RESTRICT" {
		t.Fatalf("dispatch_reservation FK = %+v, want test_run RESTRICT", fk)
	}
}

func insertReservation(t *testing.T, db *gorm.DB, runID, providerID, webdavID string) error {
	t.Helper()

	return db.Exec(`INSERT INTO dispatch_reservation
		(test_run_id, provider_id, webdav_id, shared_secret, receiver_host, share_with, probe_file_path, status, created_at)
		VALUES (?, ?, ?, 'secret', 'receiver.example', 'bob', '/probe.bin', 'dispatch_reserved', 1)`,
		runID, providerID, webdavID).Error
}

func TestDispatchReservation_Constraints(t *testing.T) {
	t.Parallel()

	db := attachFresh(t)
	createTestRun(t, db, "run-disp-1")
	createTestRun(t, db, "run-disp-2")
	createTestRun(t, db, "run-disp-3")

	if err := insertReservation(t, db, "run-disp-1", "prov-1", "wd-1"); err != nil {
		t.Fatalf("insert reservation: %v", err)
	}

	if err := insertReservation(t, db, "run-disp-1", "prov-2", "wd-2"); err == nil {
		t.Fatal("duplicate test_run_id must be rejected (PK)")
	}

	if err := insertReservation(t, db, "run-disp-2", "prov-1", "wd-2"); err == nil {
		t.Fatal("duplicate provider_id must be rejected (UNIQUE)")
	}

	if err := insertReservation(t, db, "run-disp-3", "prov-2", "wd-1"); err == nil {
		t.Fatal("duplicate webdav_id must be rejected (UNIQUE)")
	}

	if err := insertReservation(t, db, "run-disp-2", "prov-2", "wd-2"); err != nil {
		t.Fatalf("insert second reservation: %v", err)
	}

	// Validator-owned child rows restrict test_run delete: removing
	// run-disp-1 must fail while its reservation remains, then succeed after
	// the child row is deleted. The reservation on run-disp-2 must survive.
	if err := db.Exec("DELETE FROM test_run WHERE test_run_id = 'run-disp-1'").Error; err == nil {
		t.Fatal("test_run delete must be rejected while its dispatch_reservation remains")
	}

	mustExec(t, db, "DELETE FROM dispatch_reservation WHERE test_run_id = 'run-disp-1'")
	mustExec(t, db, "DELETE FROM test_run WHERE test_run_id = 'run-disp-1'")

	var resCount int64

	mustQueryCount(t, db, "SELECT COUNT(*) FROM dispatch_reservation", &resCount)

	if resCount != 1 {
		t.Fatalf("dispatch_reservation rows = %d, want 1 (only run-disp-1 removed)", resCount)
	}
}
