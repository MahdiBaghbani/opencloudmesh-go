// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"testing"

	"gorm.io/gorm"

	store "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/sqlitecore"
)

func TestSQLiteCoreOpen_DoesNotCreateValidatorTables(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	sqlCore, err := sqlitecore.Open(dir)
	if err != nil {
		t.Fatalf("sqlitecore.Open: %v", err)
	}

	db := sqlCore.DB()

	for _, table := range []string{"validator_schema", "test_run", "stats_raw", "report_exchange"} {
		if db.Migrator().HasTable(table) {
			t.Fatalf("sqlitecore.Open must not create validator table %s", table)
		}
	}

	for _, table := range []string{"outgoing_shares", "incoming_shares", "outgoing_invites", "incoming_invites"} {
		if !db.Migrator().HasTable(table) {
			t.Fatalf("sqlitecore.Open must create peer table %s", table)
		}
	}

	// A generic peer boot must not inspect validator_schema or fail closed on
	// unknown versions: seed a future version, close, and reopen.
	mustExec(t, db, "CREATE TABLE validator_schema (version INTEGER PRIMARY KEY)")
	mustExec(t, db, "INSERT INTO validator_schema (version) VALUES (99)")

	if closeErr := sqlCore.Close(); closeErr != nil {
		t.Fatalf("close: %v", closeErr)
	}

	reopened, err := sqlitecore.Open(dir)
	if err != nil {
		t.Fatalf("sqlitecore.Open with future validator_schema version must succeed: %v", err)
	}

	t.Cleanup(func() {
		if closeErr := reopened.Close(); closeErr != nil {
			t.Errorf("sqlitecore.Close: %v", closeErr)
		}
	})
}

func TestAttach_LegacyTablesRecovered(t *testing.T) {
	t.Parallel()

	sqlCore := openPeerStore(t)
	db := sqlCore.DB()

	// Peer rows predate the validator recovery and must survive it untouched.
	peerShare := store.OutgoingShare{
		ShareID:    "share-legacy",
		ProviderID: "provider-legacy",
		WebDAVID:   "webdav-legacy",
		CreatedAt:  1,
	}
	if err := db.Create(&peerShare).Error; err != nil {
		t.Fatalf("seed peer share: %v", err)
	}

	peerInvite := store.IncomingInvite{
		ID:              "invite-legacy",
		Token:           "token-legacy",
		SenderFQDN:      "sender.example",
		RecipientUserID: "alice",
		Status:          "pending",
		ReceivedAt:      1,
		UpdatedAt:       1,
	}
	if err := db.Create(&peerInvite).Error; err != nil {
		t.Fatalf("seed peer invite: %v", err)
	}

	legacyDDL := []string{
		`CREATE TABLE test_run (
			test_run_id TEXT PRIMARY KEY,
			is_active BOOLEAN NOT NULL DEFAULT FALSE,
			state TEXT NOT NULL,
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
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		)`,
		`INSERT INTO test_run (test_run_id, state, target_origin, target_host, discovery_url, jwks_uri, manifest_schema, session_kind, created_at, updated_at)
			VALUES ('legacy-run', 'created', 'https://t.example', 't.example', 'https://t.example/.well-known/ocm', 'https://t.example/jwks.json', 'ocm-validator-manifest/v1', 'passive_only', 1, 1)`,
		`CREATE TABLE stats_raw (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			host_hash TEXT NOT NULL,
			session_kind TEXT NOT NULL,
			reverse_invite_exercised BOOLEAN NOT NULL DEFAULT FALSE,
			platform TEXT NOT NULL,
			api_version TEXT NOT NULL,
			created_at INTEGER NOT NULL
		)`,
		`INSERT INTO stats_raw (host_hash, session_kind, platform, api_version, created_at) VALUES ('h', 'passive_only', 'nextcloud', '1', 1)`,
		`CREATE TABLE share_correlation (id INTEGER PRIMARY KEY AUTOINCREMENT, test_run_id TEXT NOT NULL, role TEXT NOT NULL)`,
		`INSERT INTO share_correlation (test_run_id, role) VALUES ('legacy-run', 'outgoing_invite')`,
		`CREATE TABLE stats_aggregate (id INTEGER PRIMARY KEY AUTOINCREMENT, window_days INTEGER NOT NULL)`,
		`INSERT INTO stats_aggregate (window_days) VALUES (30)`,
	}

	for _, stmt := range legacyDDL {
		mustExec(t, db, stmt)
	}

	if _, err := Attach(db, DefaultSessionConfig()); err != nil {
		t.Fatalf("Attach over legacy tables: %v", err)
	}

	info := tableInfo(t, db, "test_run")
	if _, ok := info["bob_user_id"]; !ok {
		t.Fatal("final test_run must have bob_user_id after recovery")
	}

	rawInfo := tableInfo(t, db, "stats_raw")
	if _, ok := rawInfo["k"]; !ok {
		t.Fatal("final stats_raw must have k after recovery")
	}

	var runCount, rawCount int64

	mustQueryCount(t, db, "SELECT COUNT(*) FROM test_run", &runCount)
	mustQueryCount(t, db, "SELECT COUNT(*) FROM stats_raw", &rawCount)

	if runCount != 0 || rawCount != 0 {
		t.Fatalf("legacy rows must be dropped, got test_run=%d stats_raw=%d", runCount, rawCount)
	}

	versions := schemaVersions(t, db)
	if len(versions) != 1 || versions[0] != validatorSchemaVersion {
		t.Fatalf("validator_schema rows = %v, want exactly [%d]", versions, validatorSchemaVersion)
	}

	// Recovery is table-scoped: peer tables and their rows remain intact.
	assertPeerRowsIntact(t, db)
}

// assertPeerRowsIntact proves the seeded peer rows survived validator schema
// recovery with their data unchanged.
func assertPeerRowsIntact(t *testing.T, db *gorm.DB) {
	t.Helper()

	var share store.OutgoingShare
	if err := db.First(&share, "share_id = ?", "share-legacy").Error; err != nil {
		t.Fatalf("peer outgoing_shares row must survive recovery: %v", err)
	}

	if share.ProviderID != "provider-legacy" || share.WebDAVID != "webdav-legacy" {
		t.Fatalf("peer share data corrupted by recovery: %+v", share)
	}

	var invite store.IncomingInvite
	if err := db.First(&invite, "id = ?", "invite-legacy").Error; err != nil {
		t.Fatalf("peer incoming_invites row must survive recovery: %v", err)
	}

	if invite.Token != "token-legacy" || invite.RecipientUserID != "alice" {
		t.Fatalf("peer invite data corrupted by recovery: %+v", invite)
	}
}

func TestAttach_PreservesPeerTablesAndData(t *testing.T) {
	t.Parallel()

	sqlCore := openPeerStore(t)
	db := sqlCore.DB()

	share := store.OutgoingShare{
		ShareID:    "share-peer",
		ProviderID: "provider-peer",
		WebDAVID:   "webdav-peer",
		CreatedAt:  1,
	}

	if err := db.Create(&share).Error; err != nil {
		t.Fatalf("seed outgoing share: %v", err)
	}

	invite := store.IncomingInvite{
		ID:              "invite-peer",
		Token:           "token-peer",
		RecipientUserID: "alice",
		ReceivedAt:      1,
		UpdatedAt:       1,
	}

	if err := db.Create(&invite).Error; err != nil {
		t.Fatalf("seed incoming invite: %v", err)
	}

	if _, err := Attach(db, DefaultSessionConfig()); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	var gotShare store.OutgoingShare

	if err := db.Where("provider_id = ?", "provider-peer").First(&gotShare).Error; err != nil {
		t.Fatalf("peer outgoing share must survive Attach: %v", err)
	}

	var gotInvite store.IncomingInvite

	if err := db.Where("id = ?", "invite-peer").First(&gotInvite).Error; err != nil {
		t.Fatalf("peer incoming invite must survive Attach: %v", err)
	}
}
