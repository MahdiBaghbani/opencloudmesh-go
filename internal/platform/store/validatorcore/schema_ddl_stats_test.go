// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"testing"
)

func TestStatsRawK_NotNullUnique(t *testing.T) {
	t.Parallel()

	db := attachFresh(t)
	info := tableInfo(t, db, "stats_raw")

	k, ok := info["k"]
	if !ok {
		t.Fatal("stats_raw missing column k")
	}

	if !k.NotNull {
		t.Fatal("stats_raw.k must be NOT NULL")
	}

	if k.DfltValue != nil {
		t.Fatalf("stats_raw.k must have no default, got %v", *k.DfltValue)
	}

	row := StatsRaw{
		K:           "k-dup",
		HostHash:    "host-1",
		SessionKind: SessionKindPassiveOnly,
		Platform:    "nextcloud",
		APIVersion:  "1",
		CreatedAt:   1,
	}

	if err := db.Create(&row).Error; err != nil {
		t.Fatalf("insert stats_raw with k: %v", err)
	}

	dup := row
	dup.ID = 0

	if err := db.Create(&dup).Error; err == nil {
		t.Fatal("duplicate stats_raw.k must be rejected")
	}

	err := db.Exec(`INSERT INTO stats_raw
		(host_hash, session_kind, reverse_invite_exercised, platform, api_version, created_at)
		VALUES ('host-2', 'passive_only', FALSE, 'nextcloud', '1', 1)`).Error
	if err == nil {
		t.Fatal("stats_raw insert without k must be rejected (NOT NULL)")
	}
}

func TestStatsRaw_NoWindowBucket(t *testing.T) {
	t.Parallel()

	db := attachFresh(t)
	info := tableInfo(t, db, "stats_raw")

	if _, ok := info["window_bucket"]; ok {
		t.Fatal("stats_raw must not have window_bucket")
	}

	var bucketIndex string
	if err := db.Raw(
		"SELECT sql FROM sqlite_master WHERE type = 'index' AND name = 'idx_stats_raw_window_bucket'",
	).Scan(&bucketIndex).Error; err != nil {
		t.Fatalf("probe window_bucket index: %v", err)
	}

	if bucketIndex != "" {
		t.Fatal("idx_stats_raw_window_bucket must not exist")
	}

	var kindIndex string
	if err := db.Raw(
		"SELECT sql FROM sqlite_master WHERE type = 'index' AND name = 'idx_stats_raw_session_kind'",
	).Scan(&kindIndex).Error; err != nil {
		t.Fatalf("read session_kind index: %v", err)
	}

	if kindIndex == "" {
		t.Fatal("idx_stats_raw_session_kind must exist")
	}
}

func TestStatsAggregate_Absent(t *testing.T) {
	t.Parallel()

	db := attachFresh(t)

	if db.Migrator().HasTable(tableStatsAggregate) {
		t.Fatal("stats_aggregate must not exist")
	}
}
