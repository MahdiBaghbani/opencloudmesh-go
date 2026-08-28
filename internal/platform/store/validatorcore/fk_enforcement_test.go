// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"database/sql"
	"errors"
	"testing"

	gosqlite "github.com/glebarez/go-sqlite"
)

const (
	// sqliteConstraintForeignKey is SQLITE_CONSTRAINT_FOREIGNKEY
	// (19 | (3 << 8)). Child inserts that name a missing parent surface this
	// code when the glebarez driver enables extended result codes.
	sqliteConstraintForeignKey = 787

	// sqliteConstraintTrigger is SQLITE_CONSTRAINT_TRIGGER (19 | (7 << 8)).
	// SQLite implements ON DELETE RESTRICT with generated triggers, so a
	// parent delete that would orphan children surfaces this code.
	sqliteConstraintTrigger = 1811
)

func TestReportExchange_OrphanRejectedOnBothConnections(t *testing.T) {
	t.Parallel()

	core := openMigratedProductionCore(t)

	assertOrphanInsertRejectedOnBothConnections(
		t,
		core,
		`INSERT INTO report_exchange
			(test_run_id, seq, captured_at, direction, endpoint_id, method, url, created_at)
			VALUES ('missing', ?, 1, 'out', 'discovery', 'GET', 'https://t.example/ocm', 1)`,
		[]any{1},
		[]any{2},
		"SELECT COUNT(*) FROM report_exchange WHERE test_run_id = 'missing'",
	)
}

func TestShareCorrelation_OrphanRejectedOnBothConnections(t *testing.T) {
	t.Parallel()

	core := openMigratedProductionCore(t)

	assertOrphanInsertRejectedOnBothConnections(
		t,
		core,
		`INSERT INTO share_correlation
			(test_run_id, role, sender_host, provider_id, local_identity, created_at)
			VALUES ('missing', 'outgoing_to_target', 'peer.example', ?, 'a', 1)`,
		[]any{"prov-conn-1"},
		[]any{"prov-conn-2"},
		"SELECT COUNT(*) FROM share_correlation WHERE test_run_id = 'missing'",
	)
}

func assertOrphanInsertRejectedOnBothConnections(
	t *testing.T,
	core *Core,
	insertSQL string,
	args1, args2 []any,
	countSQL string,
) {
	t.Helper()

	conn1, conn2 := acquireTwoSQLConns(t, core)
	ctx := t.Context()

	_, err1 := conn1.ExecContext(ctx, insertSQL, args1...)
	_, err2 := conn2.ExecContext(ctx, insertSQL, args2...)

	requireSQLiteForeignKeyError(t, err1)
	requireSQLiteForeignKeyError(t, err2)

	var n int64
	if scanErr := core.DB().WithContext(ctx).Raw(countSQL).Scan(&n).Error; scanErr != nil {
		t.Fatalf("count orphans: %v", scanErr)
	}

	if n != 0 {
		t.Fatalf("orphan rows = %d, want 0", n)
	}
}

func acquireTwoSQLConns(t *testing.T, core *Core) (conn1, conn2 *sql.Conn) {
	t.Helper()

	sqlDB, err := core.DB().DB()
	if err != nil {
		t.Fatalf("sql handle: %v", err)
	}

	sqlDB.SetMaxOpenConns(4)

	ctx := t.Context()

	conn1, err = sqlDB.Conn(ctx)
	if err != nil {
		t.Fatalf("acquire connection 1: %v", err)
	}

	t.Cleanup(func() {
		if closeErr := conn1.Close(); closeErr != nil {
			t.Errorf("close connection 1: %v", closeErr)
		}
	})

	conn2, err = sqlDB.Conn(ctx)
	if err != nil {
		t.Fatalf("acquire connection 2: %v", err)
	}

	t.Cleanup(func() {
		if closeErr := conn2.Close(); closeErr != nil {
			t.Errorf("close connection 2: %v", closeErr)
		}
	})

	requireConnForeignKeysOn(t, conn1)
	requireConnForeignKeysOn(t, conn2)

	return conn1, conn2
}

func requireConnForeignKeysOn(t *testing.T, conn *sql.Conn) {
	t.Helper()

	var enforced int

	if err := conn.QueryRowContext(t.Context(), "PRAGMA foreign_keys").Scan(&enforced); err != nil {
		t.Fatalf("PRAGMA foreign_keys: %v", err)
	}

	if enforced != 1 {
		t.Fatalf("PRAGMA foreign_keys = %d, want 1 on this connection", enforced)
	}
}

func requireSQLiteForeignKeyError(t *testing.T, err error) {
	t.Helper()

	if err == nil {
		t.Fatal("expected a foreign key error")
	}

	var sqliteErr *gosqlite.Error
	if !errors.As(err, &sqliteErr) {
		t.Fatalf("error = %v, want *gosqlite.Error", err)
	}

	if sqliteErr.Code() != sqliteConstraintForeignKey {
		t.Fatalf(
			"sqlite code = %d, want %d (SQLITE_CONSTRAINT_FOREIGNKEY)",
			sqliteErr.Code(),
			sqliteConstraintForeignKey,
		)
	}
}

func requireSQLiteParentRestrictError(t *testing.T, err error) {
	t.Helper()

	if err == nil {
		t.Fatal("expected a parent-delete restrict error")
	}

	var sqliteErr *gosqlite.Error
	if !errors.As(err, &sqliteErr) {
		t.Fatalf("error = %v, want *gosqlite.Error", err)
	}

	switch sqliteErr.Code() {
	case sqliteConstraintForeignKey, sqliteConstraintTrigger:
		return
	default:
		t.Fatalf(
			"sqlite code = %d, want %d (FOREIGNKEY) or %d (TRIGGER RESTRICT)",
			sqliteErr.Code(),
			sqliteConstraintForeignKey,
			sqliteConstraintTrigger,
		)
	}
}
