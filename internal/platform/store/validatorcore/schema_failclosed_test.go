// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"errors"
	"testing"

	store "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
)

func TestAttach_UnknownVersionFailsClosed(t *testing.T) {
	t.Parallel()

	sqlCore := openPeerStore(t)
	db := sqlCore.DB()

	peer := store.OutgoingShare{
		ShareID:    "share-1",
		ProviderID: "provider-1",
		WebDAVID:   "webdav-1",
		CreatedAt:  1,
	}

	if err := db.Create(&peer).Error; err != nil {
		t.Fatalf("seed peer row: %v", err)
	}

	mustExec(t, db, "CREATE TABLE validator_schema (version INTEGER PRIMARY KEY)")
	mustExec(t, db, "INSERT INTO validator_schema (version) VALUES (2)")
	// Legacy-shaped table with data: proves the failure happens before any drop.
	mustExec(t, db, "CREATE TABLE stats_raw (id INTEGER PRIMARY KEY, marker TEXT)")
	mustExec(t, db, "INSERT INTO stats_raw (id, marker) VALUES (1, 'keep')")

	_, err := Attach(db, DefaultSessionConfig())
	if err == nil {
		t.Fatal("Attach must fail on unsupported validator_schema version")
	}

	if !errors.Is(err, ErrUnsupportedValidatorSchemaVersion) {
		t.Fatalf("error = %v, want ErrUnsupportedValidatorSchemaVersion", err)
	}

	var peerCount int64

	if err := db.Model(&store.OutgoingShare{}).Count(&peerCount).Error; err != nil {
		t.Fatalf("count peer rows: %v", err)
	}

	if peerCount != 1 {
		t.Fatalf("peer rows = %d, want 1 (peer data must survive)", peerCount)
	}

	var marker string

	if err := db.Raw("SELECT marker FROM stats_raw WHERE id = 1").Scan(&marker).Error; err != nil {
		t.Fatalf("legacy stats_raw must survive failed Attach: %v", err)
	}

	if marker != "keep" {
		t.Fatalf("legacy stats_raw marker = %q, want keep (no destructive action)", marker)
	}

	if db.Migrator().HasTable("test_run") {
		t.Fatal("test_run must not be created when version check fails")
	}
}

func TestAttach_MalformedVersionOneFailsClosed(t *testing.T) {
	t.Parallel()

	sqlCore := openPeerStore(t)
	db := sqlCore.DB()

	peer := store.OutgoingShare{
		ShareID:    "share-mal",
		ProviderID: "provider-mal",
		WebDAVID:   "webdav-mal",
		CreatedAt:  1,
	}

	if err := db.Create(&peer).Error; err != nil {
		t.Fatalf("seed peer row: %v", err)
	}

	// All validator tables exist and version 1 is recorded, but the shapes are
	// wrong: no state CHECK, no bob_user_id, no stats_raw.k, no slot indexes.
	malformed := []string{
		`CREATE TABLE test_run (
			test_run_id TEXT PRIMARY KEY,
			state TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		)`,
		`CREATE TABLE share_correlation (id INTEGER PRIMARY KEY AUTOINCREMENT, test_run_id TEXT NOT NULL, role TEXT NOT NULL)`,
		`CREATE TABLE stats_raw (id INTEGER PRIMARY KEY AUTOINCREMENT, host_hash TEXT NOT NULL)`,
		`CREATE TABLE stats_aggregate (host_hash TEXT PRIMARY KEY)`,
		`CREATE TABLE report_exchange (exchange_id INTEGER PRIMARY KEY AUTOINCREMENT, test_run_id TEXT NOT NULL)`,
		`CREATE TABLE evidence_row (id INTEGER PRIMARY KEY AUTOINCREMENT, test_run_id TEXT NOT NULL)`,
		`CREATE TABLE dispatch_reservation (test_run_id TEXT PRIMARY KEY)`,
		`CREATE TABLE validator_schema (version INTEGER PRIMARY KEY)`,
		`INSERT INTO validator_schema (version) VALUES (1)`,
	}

	for _, stmt := range malformed {
		mustExec(t, db, stmt)
	}

	_, err := Attach(db, DefaultSessionConfig())
	if err == nil {
		t.Fatal("Attach must fail closed on a malformed version-1 schema")
	}

	// No repair and no destructive action: the malformed shape must remain.
	info := tableInfo(t, db, "stats_raw")
	if _, ok := info["k"]; ok {
		t.Fatal("malformed stats_raw must not be repaired with a k column")
	}

	runInfo := tableInfo(t, db, "test_run")
	if _, ok := runInfo["bob_user_id"]; ok {
		t.Fatal("malformed test_run must not be repaired with bob_user_id")
	}

	var peerCount int64

	mustQueryCount(t, db, "SELECT COUNT(*) FROM outgoing_shares", &peerCount)

	if peerCount != 1 {
		t.Fatalf("peer rows = %d, want 1 (peer data must survive)", peerCount)
	}
}
