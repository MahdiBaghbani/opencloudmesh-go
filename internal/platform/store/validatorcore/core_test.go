// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	gormsqlite "github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func openTestCore(t *testing.T) *Core {
	t.Helper()

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "validator-test.db")

	db, err := gorm.Open(gormsqlite.Open(dbPath), &gorm.Config{
		Logger:         logger.Default.LogMode(logger.Silent),
		TranslateError: true,
	})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}

	if err := MigrateModels(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	t.Cleanup(func() {
		sqlDB, dbErr := db.DB()
		if dbErr == nil {
			if closeErr := sqlDB.Close(); closeErr != nil {
				t.Errorf("close db: %v", closeErr)
			}
		}

		if rmErr := os.RemoveAll(dir); rmErr != nil {
			t.Errorf("remove temp dir: %v", rmErr)
		}
	})

	return NewCore(db)
}

func TestShareCorrelation_UniqueCompositeIndex(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()

	runID := "run-unique"
	if err := core.DB().WithContext(ctx).Create(&TestRun{
		TestRunID:   runID,
		IsActive:    true,
		State:       StateActiveRunning,
		SessionKind: SessionKindActiveFull,
		TargetHost:  "unique.example",
		CreatedAt:   1,
		UpdatedAt:   1,
	}).Error; err != nil {
		t.Fatalf("create test run: %v", err)
	}

	first := ShareCorrelation{
		TestRunID:     runID,
		Role:          RoleOutgoingToTarget,
		SenderHost:    "unique.example",
		ProviderID:    "share-unique-1",
		LocalIdentity: LocalIdentityA,
		Status:        CorrelationStatusConfirmed,
		CreatedAt:     1,
	}

	if err := core.DB().WithContext(ctx).Create(&first).Error; err != nil {
		t.Fatalf("create first correlation: %v", err)
	}

	duplicate := ShareCorrelation{
		TestRunID:     runID,
		Role:          RoleOutgoingToTarget,
		SenderHost:    "unique.example",
		ProviderID:    "share-unique-1",
		LocalIdentity: LocalIdentityA,
		Status:        CorrelationStatusPending,
		CreatedAt:     2,
	}

	err := core.DB().WithContext(ctx).Create(&duplicate).Error
	if err == nil {
		t.Fatal("expected duplicate share_correlation insert to fail")
	}

	if !errors.Is(err, gorm.ErrDuplicatedKey) {
		t.Fatalf("duplicate insert error = %v, want gorm.ErrDuplicatedKey", err)
	}
}

func TestShareCorrelation_UniqueCompositeIndex_LocalIdentityCoexistence(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()

	runID := "run-local-identity"
	if err := core.DB().WithContext(ctx).Create(&TestRun{
		TestRunID:   runID,
		IsActive:    true,
		State:       StateActiveRunning,
		SessionKind: SessionKindActiveFull,
		TargetHost:  "identity.example",
		CreatedAt:   1,
		UpdatedAt:   1,
	}).Error; err != nil {
		t.Fatalf("create test run: %v", err)
	}

	base := ShareCorrelation{
		TestRunID:  runID,
		Role:       RoleOutgoingToTarget,
		SenderHost: "identity.example",
		ProviderID: "share-identity-1",
		Status:     CorrelationStatusConfirmed,
		CreatedAt:  1,
	}

	identityA := base
	identityA.LocalIdentity = LocalIdentityA

	if err := core.DB().WithContext(ctx).Create(&identityA).Error; err != nil {
		t.Fatalf("create identity A correlation: %v", err)
	}

	identityB := base
	identityB.LocalIdentity = LocalIdentityB
	identityB.CreatedAt = 2

	if err := core.DB().WithContext(ctx).Create(&identityB).Error; err != nil {
		t.Fatalf("create identity B correlation: %v", err)
	}

	duplicate := base
	duplicate.LocalIdentity = LocalIdentityA
	duplicate.Status = CorrelationStatusPending
	duplicate.CreatedAt = 3

	err := core.DB().WithContext(ctx).Create(&duplicate).Error
	if err == nil {
		t.Fatal("expected duplicate share_correlation insert to fail")
	}

	if !errors.Is(err, gorm.ErrDuplicatedKey) {
		t.Fatalf("duplicate insert error = %v, want gorm.ErrDuplicatedKey", err)
	}
}

func TestShareCorrelation_DefaultStatusConfirmed(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()

	runID := "run-default-status"
	if err := core.DB().WithContext(ctx).Create(&TestRun{
		TestRunID:   runID,
		IsActive:    true,
		State:       StateActiveRunning,
		SessionKind: SessionKindActiveFull,
		TargetHost:  "default.example",
		CreatedAt:   1,
		UpdatedAt:   1,
	}).Error; err != nil {
		t.Fatalf("create test run: %v", err)
	}

	row := ShareCorrelation{
		TestRunID:     runID,
		Role:          RoleIncomingFromTarget,
		SenderHost:    "default.example",
		ProviderID:    "share-default-1",
		LocalIdentity: LocalIdentityB,
		CreatedAt:     1,
	}

	if err := core.DB().WithContext(ctx).Omit("Status").Create(&row).Error; err != nil {
		t.Fatalf("create correlation without status: %v", err)
	}

	var stored ShareCorrelation
	if err := core.DB().WithContext(ctx).First(&stored, row.ID).Error; err != nil {
		t.Fatalf("load correlation: %v", err)
	}

	if stored.Status != CorrelationStatusConfirmed {
		t.Fatalf("status = %q, want %q", stored.Status, CorrelationStatusConfirmed)
	}
}
