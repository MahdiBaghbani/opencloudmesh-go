// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// ocmgo:file-length-ignore: validator schema apply, recovery, and fail-closed coverage

package validatorcore

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	store "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/sqlitecore"
)

// openSchemaTestDB opens a bare SQLite/GORM handle with foreign-key
// enforcement enabled on every pooled connection, matching the production
// sqlitecore DSN, so schema tests exercise real FK constraints.
func openSchemaTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "ocm.db")

	db, err := gorm.Open(sqlite.Open(dbPath+"?_pragma=foreign_keys(1)"), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}

	t.Cleanup(func() {
		sqlDB, err := db.DB()
		if err != nil {
			t.Errorf("sql handle: %v", err)

			return
		}

		if closeErr := sqlDB.Close(); closeErr != nil {
			t.Errorf("close sqlite: %v", closeErr)
		}
	})

	requireForeignKeysOn(t, db)

	return db
}

// requireForeignKeysOn proves the test handle enforces foreign keys; without
// it, cascade and SET NULL tests would silently pass against a disabled
// constraint engine.
func requireForeignKeysOn(t *testing.T, db *gorm.DB) {
	t.Helper()

	var enforced int

	if err := db.Raw("PRAGMA foreign_keys").Scan(&enforced).Error; err != nil {
		t.Fatalf("read PRAGMA foreign_keys: %v", err)
	}

	if enforced != 1 {
		t.Fatalf("PRAGMA foreign_keys = %d, want 1 (schema tests must enforce FK constraints)", enforced)
	}
}

func openPeerStore(t *testing.T) *sqlitecore.Core {
	t.Helper()

	sqlCore, err := sqlitecore.Open(t.TempDir())
	if err != nil {
		t.Fatalf("sqlitecore.Open: %v", err)
	}

	t.Cleanup(func() {
		if closeErr := sqlCore.Close(); closeErr != nil {
			t.Errorf("sqlitecore.Close: %v", closeErr)
		}
	})

	requireForeignKeysOn(t, sqlCore.DB())

	return sqlCore
}

func attachFresh(t *testing.T) *gorm.DB {
	t.Helper()

	sqlCore := openPeerStore(t)

	if _, err := Attach(sqlCore.DB(), DefaultSessionConfig()); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	return sqlCore.DB()
}

func mustExec(t *testing.T, db *gorm.DB, query string) {
	t.Helper()

	if err := db.Exec(query).Error; err != nil {
		t.Fatalf("exec: %v\n%s", err, query)
	}
}

func tableSQL(t *testing.T, db *gorm.DB, table string) string {
	t.Helper()

	var sqlText string

	if err := db.Raw(
		"SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?", table,
	).Scan(&sqlText).Error; err != nil {
		t.Fatalf("read sqlite_master for %s: %v", table, err)
	}

	return sqlText
}

type pragmaColumn struct {
	CID       int     `gorm:"column:cid"`
	Name      string  `gorm:"column:name"`
	Type      string  `gorm:"column:type"`
	NotNull   bool    `gorm:"column:notnull"`
	DfltValue *string `gorm:"column:dflt_value"`
	PK        int     `gorm:"column:pk"`
}

func tableInfo(t *testing.T, db *gorm.DB, table string) map[string]pragmaColumn {
	t.Helper()

	var cols []pragmaColumn

	if err := db.Raw("PRAGMA table_info(" + table + ")").Scan(&cols).Error; err != nil {
		t.Fatalf("PRAGMA table_info(%s): %v", table, err)
	}

	out := make(map[string]pragmaColumn, len(cols))

	for _, c := range cols {
		out[c.Name] = c
	}

	if len(out) == 0 {
		t.Fatalf("table %s has no columns (missing?)", table)
	}

	return out
}

type pragmaFK struct {
	ID       int    `gorm:"column:id"`
	Seq      int    `gorm:"column:seq"`
	Table    string `gorm:"column:table"`
	From     string `gorm:"column:from"`
	To       string `gorm:"column:to"`
	OnUpdate string `gorm:"column:on_update"`
	OnDelete string `gorm:"column:on_delete"`
	Match    string `gorm:"column:match"`
}

func foreignKeys(t *testing.T, db *gorm.DB, table string) []pragmaFK {
	t.Helper()

	var fks []pragmaFK

	if err := db.Raw("PRAGMA foreign_key_list(" + table + ")").Scan(&fks).Error; err != nil {
		t.Fatalf("PRAGMA foreign_key_list(%s): %v", table, err)
	}

	return fks
}

func findFK(fks []pragmaFK, from string) *pragmaFK {
	for i := range fks {
		if fks[i].From == from {
			return &fks[i]
		}
	}

	return nil
}

func createTestRun(t *testing.T, db *gorm.DB, id string) {
	t.Helper()

	run := TestRun{
		TestRunID:      id,
		State:          StateCreated,
		TargetOrigin:   "https://target.example",
		TargetHost:     "target.example",
		DiscoveryURL:   "https://target.example/.well-known/ocm",
		JwksURI:        "https://target.example/jwks.json",
		ManifestSchema: "ocm-validator-manifest/v1",
		SessionKind:    SessionKindPassiveOnly,
		CreatedAt:      time.Now().Unix(),
		UpdatedAt:      time.Now().Unix(),
	}

	if err := db.Create(&run).Error; err != nil {
		t.Fatalf("create test_run %s: %v", id, err)
	}
}

func schemaVersions(t *testing.T, db *gorm.DB) []int {
	t.Helper()

	var versions []int

	if err := db.Raw("SELECT version FROM validator_schema").Scan(&versions).Error; err != nil {
		t.Fatalf("read validator_schema: %v", err)
	}

	return versions
}

func TestApplyValidatorSchema_CreatesVersionOne(t *testing.T) {
	t.Parallel()

	db := openSchemaTestDB(t)

	if err := ApplyValidatorSchema(db); err != nil {
		t.Fatalf("ApplyValidatorSchema: %v", err)
	}

	versions := schemaVersions(t, db)
	if len(versions) != 1 || versions[0] != validatorSchemaVersion {
		t.Fatalf("validator_schema rows = %v, want exactly [%d]", versions, validatorSchemaVersion)
	}

	for _, table := range []string{
		"test_run", "share_correlation", "report_exchange", "evidence_row",
		"dispatch_reservation", "stats_raw", "stats_aggregate", "validator_schema",
	} {
		if !db.Migrator().HasTable(table) {
			t.Fatalf("table %s missing after ApplyValidatorSchema", table)
		}
	}
}

func TestApplyValidatorSchema_Idempotent(t *testing.T) {
	t.Parallel()

	db := openSchemaTestDB(t)

	if err := ApplyValidatorSchema(db); err != nil {
		t.Fatalf("first apply: %v", err)
	}

	createTestRun(t, db, "run-idem")

	if err := ApplyValidatorSchema(db); err != nil {
		t.Fatalf("second apply: %v", err)
	}

	var count int64

	if err := db.Model(&TestRun{}).Where("test_run_id = ?", "run-idem").Count(&count).Error; err != nil {
		t.Fatalf("count test_run: %v", err)
	}

	if count != 1 {
		t.Fatalf("test_run row lost on re-apply, count = %d", count)
	}

	versions := schemaVersions(t, db)
	if len(versions) != 1 || versions[0] != validatorSchemaVersion {
		t.Fatalf("validator_schema rows = %v, want exactly [%d]", versions, validatorSchemaVersion)
	}
}

func TestApplyValidatorSchema_NilDB(t *testing.T) {
	t.Parallel()

	if err := ApplyValidatorSchema(nil); err == nil {
		t.Fatal("expected error for nil db")
	}
}

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

func mustQueryCount(t *testing.T, db *gorm.DB, query string, dest *int64) {
	t.Helper()

	if err := db.Raw(query).Scan(dest).Error; err != nil {
		t.Fatalf("query: %v\n%s", err, query)
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
