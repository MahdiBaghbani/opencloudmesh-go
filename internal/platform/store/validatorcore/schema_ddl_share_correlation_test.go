// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"slices"
	"strings"
	"sync"
	"testing"

	gormschema "gorm.io/gorm/schema"
)

func TestShareCorrelation_ColumnsAndFK(t *testing.T) {
	t.Parallel()

	db := attachFresh(t)
	info := tableInfo(t, db, "share_correlation")

	if info["id"].PK != 1 {
		t.Fatal("share_correlation.id must be the primary key")
	}

	if !info["test_run_id"].NotNull {
		t.Fatal("share_correlation.test_run_id must be NOT NULL")
	}

	if info["local_identity"].DfltValue != nil {
		t.Fatalf("local_identity must have no database default, got %v", *info["local_identity"].DfltValue)
	}

	fks := foreignKeys(t, db, "share_correlation")
	fk := findFK(fks, "test_run_id")

	if fk == nil || fk.Table != "test_run" || fk.OnUpdate != "CASCADE" || fk.OnDelete != "RESTRICT" {
		t.Fatalf("share_correlation FK = %+v, want test_run CASCADE/RESTRICT", fk)
	}
}

func newCorrelation(role, providerID, identity string) ShareCorrelation {
	return ShareCorrelation{
		TestRunID:     "run-corr",
		Role:          role,
		SenderHost:    "sender.example",
		ProviderID:    providerID,
		LocalIdentity: identity,
		Status:        "ok",
		CreatedAt:     1,
	}
}

func TestShareCorrelation_RoleSlotsAndComposite(t *testing.T) {
	t.Parallel()

	db := attachFresh(t)
	createTestRun(t, db, "run-corr")

	outgoing := newCorrelation(RoleOutgoingInvite, "prov-a", "alice")

	if err := db.Create(&outgoing).Error; err != nil {
		t.Fatalf("insert outgoing invite: %v", err)
	}

	second := newCorrelation(RoleOutgoingInvite, "prov-b", "bob")

	if err := db.Create(&second).Error; err != nil {
		t.Fatalf("second outgoing_invite row with a distinct composite must be accepted: %v", err)
	}

	incoming := newCorrelation(RoleIncomingInvite, "prov-c", "carol")

	if err := db.Create(&incoming).Error; err != nil {
		t.Fatalf("insert incoming invite: %v", err)
	}

	incoming2 := newCorrelation(RoleIncomingInvite, "prov-d", "dave")

	if err := db.Create(&incoming2).Error; err == nil {
		t.Fatal("second incoming_invite slot row must be rejected")
	}

	nonSlot1 := newCorrelation(RoleOutgoingToTarget, "prov-e", "erin")
	nonSlot2 := newCorrelation(RoleOutgoingToTarget, "prov-f", "frank")

	if err := db.Create(&nonSlot1).Error; err != nil {
		t.Fatalf("insert non-slot row: %v", err)
	}

	if err := db.Create(&nonSlot2).Error; err != nil {
		t.Fatal("non-slot roles must allow multiple rows per run")
	}

	dupComposite := newCorrelation(RoleOutgoingToTarget, "prov-e", "erin")

	if err := db.Create(&dupComposite).Error; err == nil {
		t.Fatal("duplicate composite (test_run_id, role, sender_host, provider_id, local_identity) must be rejected")
	}
}

func TestShareCorrelation_LockedSlotIndexNames(t *testing.T) {
	t.Parallel()

	db := attachFresh(t)

	var incomingSQL string

	if err := db.Raw(
		"SELECT sql FROM sqlite_master WHERE type = 'index' AND name = ?",
		"idx_share_corr_incoming_invite_slot",
	).Scan(&incomingSQL).Error; err != nil {
		t.Fatalf("read incoming slot index: %v", err)
	}

	if incomingSQL == "" || !strings.Contains(strings.ToUpper(incomingSQL), "UNIQUE") {
		t.Fatalf("incoming slot index must exist as unique, got %q", incomingSQL)
	}

	var outgoingSQL string

	if err := db.Raw(
		"SELECT sql FROM sqlite_master WHERE type = 'index' AND name = ?",
		"idx_share_corr_outgoing_invite_slot",
	).Scan(&outgoingSQL).Error; err != nil {
		t.Fatalf("probe outgoing slot index: %v", err)
	}

	if outgoingSQL != "" {
		t.Fatal("idx_share_corr_outgoing_invite_slot must not exist")
	}
}

// TestShareCorrelation_GORMIndexTagsMatchContract proves the ShareCorrelation
// GORM tags resolve to exactly the share_correlation indexes pinned by
// validatorIndexContract: name, uniqueness, column order, and partial
// predicate all agree.
func TestShareCorrelation_GORMIndexTagsMatchContract(t *testing.T) {
	t.Parallel()

	parsed, err := gormschema.Parse(&ShareCorrelation{}, &sync.Map{}, gormschema.NamingStrategy{})
	if err != nil {
		t.Fatalf("parse ShareCorrelation: %v", err)
	}

	indexes := map[string]*gormschema.Index{}

	for _, index := range parsed.ParseIndexes() {
		indexes[index.Name] = index
	}

	for _, want := range validatorIndexContract {
		if want.table != tableShareCorrelation {
			continue
		}

		index, ok := indexes[want.name]
		if !ok {
			t.Fatalf("ShareCorrelation GORM tags missing index %s", want.name)
		}

		if unique := index.Class == "UNIQUE"; unique != want.unique {
			t.Fatalf("index %s unique = %v, want %v", want.name, unique, want.unique)
		}

		if index.Where != want.partial {
			t.Fatalf("index %s where = %q, want %q", want.name, index.Where, want.partial)
		}

		var columns []string

		for _, field := range index.Fields {
			columns = append(columns, field.DBName)
		}

		if !slices.Equal(columns, want.columns) {
			t.Fatalf("index %s columns = %v, want %v", want.name, columns, want.columns)
		}
	}
}
