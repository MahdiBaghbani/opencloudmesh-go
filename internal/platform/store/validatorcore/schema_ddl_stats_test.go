// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"strings"
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

func TestStatsAggregate_Schema(t *testing.T) {
	t.Parallel()

	db := attachFresh(t)
	info := tableInfo(t, db, "stats_aggregate")

	// Exact column set in declaration order: host_hash PK plus six NOT NULL
	// metric columns, nothing else. SQLite reports a TEXT PRIMARY KEY column
	// as nullable in PRAGMA table_info (the historical SQLite quirk), so
	// host_hash is pinned by key position and type, not by the NOT NULL flag.
	expected := []struct {
		name string
		pk   int
	}{
		{"host_hash", 1},
		{"total_sessions", 0},
		{"healthy_sessions", 0},
		{"last_platform", 0},
		{"last_healthy", 0},
		{"first_seen_ts", 0},
		{"last_seen_ts", 0},
	}

	if len(info) != len(expected) {
		t.Fatalf("stats_aggregate has %d columns, want %d", len(info), len(expected))
	}

	for _, col := range expected {
		got, ok := info[col.name]
		if !ok {
			t.Fatalf("stats_aggregate missing column %s", col.name)
		}

		if got.PK != col.pk {
			t.Fatalf("stats_aggregate.%s pk = %d, want %d", col.name, got.PK, col.pk)
		}

		if got.DfltValue != nil {
			t.Fatalf("stats_aggregate.%s must have no default, got %v", col.name, *got.DfltValue)
		}

		if col.name == "host_hash" {
			continue
		}

		if !got.NotNull {
			t.Fatalf("stats_aggregate.%s must be NOT NULL", col.name)
		}
	}

	if got := info["host_hash"]; !strings.EqualFold(got.Type, "TEXT") {
		t.Fatalf("stats_aggregate.host_hash must be TEXT, got %q", got.Type)
	}

	// The locked last-seen index must exist with exactly last_seen_ts as its
	// single indexed column.
	var indexSQL string

	if err := db.Raw(
		"SELECT sql FROM sqlite_master WHERE type = 'index' AND name = ?", "idx_stats_agg_last_seen",
	).Scan(&indexSQL).Error; err != nil {
		t.Fatalf("read idx_stats_agg_last_seen: %v", err)
	}

	if indexSQL == "" {
		t.Fatal("index idx_stats_agg_last_seen missing")
	}

	if strings.Contains(strings.ToUpper(indexSQL), "UNIQUE") {
		t.Fatalf("idx_stats_agg_last_seen must not be UNIQUE: %s", indexSQL)
	}

	var indexed []struct {
		Seqno int    `gorm:"column:seqno"`
		CID   int    `gorm:"column:cid"`
		Name  string `gorm:"column:name"`
	}

	if err := db.Raw("PRAGMA index_info(idx_stats_agg_last_seen)").Scan(&indexed).Error; err != nil {
		t.Fatalf("PRAGMA index_info(idx_stats_agg_last_seen): %v", err)
	}

	if len(indexed) != 1 || indexed[0].Name != "last_seen_ts" {
		t.Fatalf("idx_stats_agg_last_seen columns = %+v, want [last_seen_ts]", indexed)
	}
}

func TestStatsAggregate_Constraints(t *testing.T) {
	t.Parallel()

	db := attachFresh(t)

	row := StatsAggregate{
		HostHash:        "host-agg",
		TotalSessions:   3,
		HealthySessions: 2,
		LastPlatform:    "nextcloud",
		LastHealthy:     true,
		FirstSeenTS:     10,
		LastSeenTS:      30,
	}

	if err := db.Create(&row).Error; err != nil {
		t.Fatalf("insert stats_aggregate: %v", err)
	}

	// host_hash is the primary key: a second row with the same host_hash must
	// be rejected.
	dup := row
	if err := db.Create(&dup).Error; err == nil {
		t.Fatal("duplicate stats_aggregate.host_hash must be rejected")
	}

	// Every metric column is NOT NULL: omitting one must be rejected.
	err := db.Exec(`INSERT INTO stats_aggregate
		(host_hash, total_sessions, healthy_sessions, last_platform, last_healthy, first_seen_ts)
		VALUES ('host-agg-2', 1, 1, 'nextcloud', TRUE, 1)`).Error
	if err == nil {
		t.Fatal("stats_aggregate insert without last_seen_ts must be rejected (NOT NULL)")
	}
}
