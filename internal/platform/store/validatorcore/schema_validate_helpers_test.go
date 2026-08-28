// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	"gorm.io/gorm"

	store "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
)

const (
	foundV1NoTouchShareID  = "share-drift-notouch"
	foundV1NoTouchInviteID = "invite-drift-notouch"
	foundV1NoTouchStatsK   = "k-drift-notouch"
)

var foundV1NoTouchValidatorTables = []string{
	tableTestRun,
	tableShareCorrelation,
	tableStatsRaw,
	tableReportExchange,
	tableEvidenceRow,
	tableDispatchReservation,
	tableValidatorSchema,
}

// mustExecSQL runs query on the raw *sql.DB and fails the test on error.
func mustExecSQL(t *testing.T, sqlDB *sql.DB, query string) {
	t.Helper()

	if _, err := sqlDB.ExecContext(context.Background(), query); err != nil {
		t.Fatalf("exec: %v\n%s", err, query)
	}
}

// insertErrSQL runs an insert that must fail and returns the real typed driver
// error wrapped once with %w, so classifier tests exercise the same errors.As
// unwrapping to *gosqlite.Error and Code() == 275 (SQLITE_CONSTRAINT_CHECK)
// that the probe relies on when it inspects a real driver error.
func insertErrSQL(t *testing.T, sqlDB *sql.DB, query string) error {
	t.Helper()

	_, err := sqlDB.ExecContext(context.Background(), query)
	if err == nil {
		t.Fatalf("insert must fail: %s", query)
	}

	return fmt.Errorf("probe classify insert: %w", err)
}

func seedFoundV1NoTouchRows(t *testing.T, db *gorm.DB) {
	t.Helper()

	peer := store.OutgoingShare{
		ShareID:    foundV1NoTouchShareID,
		ProviderID: "provider-drift-notouch",
		WebDAVID:   "webdav-drift-notouch",
		CreatedAt:  1,
	}
	if err := db.Create(&peer).Error; err != nil {
		t.Fatalf("seed peer share: %v", err)
	}

	invite := store.IncomingInvite{
		ID:              foundV1NoTouchInviteID,
		Token:           "token-drift-notouch",
		SenderFQDN:      "sender.example",
		RecipientUserID: "alice",
		Status:          "pending",
		ReceivedAt:      1,
		UpdatedAt:       1,
	}
	if err := db.Create(&invite).Error; err != nil {
		t.Fatalf("seed peer invite: %v", err)
	}

	// stats_raw is validator-owned and is not used by CHECK probes, so a
	// marker row can prove the refuse path leaves validator data in place
	// without colliding with state or flag inserts.
	raw := StatsRaw{
		K:           foundV1NoTouchStatsK,
		HostHash:    "hash-drift-notouch",
		SessionKind: SessionKindPassiveOnly,
		Platform:    "nextcloud",
		APIVersion:  "1.1",
		CreatedAt:   1,
	}
	if err := db.Create(&raw).Error; err != nil {
		t.Fatalf("seed validator stats_raw: %v", err)
	}
}

type foundV1NoTouchSnapshot struct {
	tablePresent map[string]bool
	tableCounts  map[string]int64
	statsK       string
	share        store.OutgoingShare
	invite       store.IncomingInvite
}

func snapshotFoundV1NoTouch(t *testing.T, db *gorm.DB) foundV1NoTouchSnapshot {
	t.Helper()

	snap := foundV1NoTouchSnapshot{
		tablePresent: make(map[string]bool, len(foundV1NoTouchValidatorTables)),
		tableCounts:  make(map[string]int64, len(foundV1NoTouchValidatorTables)),
	}

	for _, table := range foundV1NoTouchValidatorTables {
		if !db.Migrator().HasTable(table) {
			snap.tablePresent[table] = false

			continue
		}

		snap.tablePresent[table] = true

		var count int64

		mustQueryCount(t, db, "SELECT COUNT(*) FROM "+table, &count)
		snap.tableCounts[table] = count
	}

	if err := db.First(&snap.share, "share_id = ?", foundV1NoTouchShareID).Error; err != nil {
		t.Fatalf("snapshot peer share: %v", err)
	}

	if err := db.First(&snap.invite, "id = ?", foundV1NoTouchInviteID).Error; err != nil {
		t.Fatalf("snapshot peer invite: %v", err)
	}

	if snap.tablePresent[tableStatsRaw] {
		var raw StatsRaw
		if err := db.First(&raw, "k = ?", foundV1NoTouchStatsK).Error; err == nil {
			snap.statsK = raw.K
		}
	}

	return snap
}

func assertFoundV1NoTouch(t *testing.T, db *gorm.DB, want foundV1NoTouchSnapshot) {
	t.Helper()

	got := snapshotFoundV1NoTouch(t, db)

	for _, table := range foundV1NoTouchValidatorTables {
		if got.tablePresent[table] != want.tablePresent[table] {
			t.Fatalf(
				"table %s present = %v, want %v (hard-refuse must not repair)",
				table, got.tablePresent[table], want.tablePresent[table],
			)
		}

		if got.tableCounts[table] != want.tableCounts[table] {
			t.Fatalf(
				"table %s count = %d, want %d (validator data must be untouched)",
				table, got.tableCounts[table], want.tableCounts[table],
			)
		}
	}

	if got.share.ShareID != want.share.ShareID ||
		got.share.ProviderID != want.share.ProviderID ||
		got.share.WebDAVID != want.share.WebDAVID {
		t.Fatalf("peer share changed after hard-refuse: %+v", got.share)
	}

	if got.invite.ID != want.invite.ID ||
		got.invite.Token != want.invite.Token ||
		got.invite.RecipientUserID != want.invite.RecipientUserID {
		t.Fatalf("peer invite changed after hard-refuse: %+v", got.invite)
	}

	if got.statsK != want.statsK {
		t.Fatalf("validator stats_raw k = %q, want %q (validator data must be untouched)", got.statsK, want.statsK)
	}
}
