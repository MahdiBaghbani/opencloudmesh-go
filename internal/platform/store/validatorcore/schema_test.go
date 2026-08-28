// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

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
// it, RESTRICT and SET NULL tests would silently pass against a disabled
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

func mustQueryCount(t *testing.T, db *gorm.DB, query string, dest *int64) {
	t.Helper()

	if err := db.Raw(query).Scan(dest).Error; err != nil {
		t.Fatalf("query: %v\n%s", err, query)
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
		"dispatch_reservation", "stats_raw", "validator_schema",
	} {
		if !db.Migrator().HasTable(table) {
			t.Fatalf("table %s missing after ApplyValidatorSchema", table)
		}
	}

	if db.Migrator().HasTable(tableStatsAggregate) {
		t.Fatal("stats_aggregate must not exist after ApplyValidatorSchema")
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
