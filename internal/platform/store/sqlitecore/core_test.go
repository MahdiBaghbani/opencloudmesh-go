// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package sqlitecore_test

import (
	"database/sql"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/sqlitecore"
)

func TestOpen_DoesNotCreateValidatorTables(t *testing.T) {
	t.Parallel()

	core, err := sqlitecore.Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	t.Cleanup(func() {
		if closeErr := core.Close(); closeErr != nil {
			t.Errorf("Close: %v", closeErr)
		}
	})

	for _, name := range []string{"test_run", "share_correlation", "stats_raw", "stats_aggregate"} {
		if core.DB().Migrator().HasTable(name) {
			t.Fatalf("sqlitecore.Open must not create validator table %q", name)
		}
	}
}

func TestOpen_ForeignKeysEnabledOnPooledConnections(t *testing.T) {
	t.Parallel()

	core, err := sqlitecore.Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	t.Cleanup(func() {
		if closeErr := core.Close(); closeErr != nil {
			t.Errorf("Close: %v", closeErr)
		}
	})

	sqlDB, err := core.DB().DB()
	if err != nil {
		t.Fatalf("DB(): %v", err)
	}

	ctx := t.Context()

	const numConns = 4

	conns := make([]*sql.Conn, numConns)

	closeConns := func() {
		for i, conn := range conns {
			if conn == nil {
				continue
			}

			if closeErr := conn.Close(); closeErr != nil {
				t.Errorf("close conn %d: %v", i, closeErr)
			}
		}
	}
	defer closeConns()

	type connResult struct {
		idx  int
		conn *sql.Conn
		err  error
	}

	results := make(chan connResult, numConns)
	for i := range numConns {
		go func(i int) {
			conn, err := sqlDB.Conn(ctx)
			results <- connResult{idx: i, conn: conn, err: err}
		}(i)
	}

	for range numConns {
		r := <-results
		if r.err != nil {
			t.Fatalf("Conn %d: %v", r.idx, r.err)
		}

		conns[r.idx] = r.conn
	}

	for i, conn := range conns {
		var fk sql.NullInt64

		if err := conn.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&fk); err != nil {
			t.Fatalf("PRAGMA foreign_keys on conn %d: %v", i, err)
		}

		if !fk.Valid || fk.Int64 != 1 {
			t.Fatalf("conn %d: foreign_keys = %v, want 1", i, fk)
		}
	}
}
