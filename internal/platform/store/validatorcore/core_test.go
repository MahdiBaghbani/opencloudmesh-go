// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// ocmgo:file-length-ignore: validator core storage, statistics rebuild, correlation, retention, and health coverage

package validatorcore

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

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

func TestMigrateModels_CreatesValidatorTables(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)

	tables := []string{"test_run", "share_correlation", "stats_raw", "stats_aggregate"}
	for _, name := range tables {
		if !core.DB().Migrator().HasTable(name) {
			t.Fatalf("expected table %q", name)
		}
	}
}

func TestIncrementStatsAggregate_PreservesCounts(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()

	pass := GradePass

	raw1 := &StatsRaw{
		HostHash:       "hash-a",
		SessionKind:    SessionKindPassiveOnly,
		Platform:       "Nextcloud",
		GradeDiscovery: new(pass),
		CreatedAt:      100,
	}

	if err := core.InsertStatsRaw(ctx, raw1); err != nil {
		t.Fatalf("insert raw: %v", err)
	}

	if err := core.IncrementStatsAggregate(ctx, raw1); err != nil {
		t.Fatalf("increment first: %v", err)
	}

	raw2 := &StatsRaw{
		HostHash:       "hash-a",
		SessionKind:    SessionKindActiveFull,
		Platform:       "CERNBox",
		GradeDiscovery: new(GradeFail),
		CreatedAt:      200,
	}

	if err := core.InsertStatsRaw(ctx, raw2); err != nil {
		t.Fatalf("insert raw 2: %v", err)
	}

	if err := core.IncrementStatsAggregate(ctx, raw2); err != nil {
		t.Fatalf("increment second: %v", err)
	}

	var agg StatsAggregate
	if err := core.DB().WithContext(ctx).First(&agg, "host_hash = ?", "hash-a").Error; err != nil {
		t.Fatalf("load aggregate: %v", err)
	}

	if agg.TotalSessions != 2 {
		t.Fatalf("total_sessions = %d, want 2", agg.TotalSessions)
	}

	if agg.HealthySessions != 1 {
		t.Fatalf("healthy_sessions = %d, want 1", agg.HealthySessions)
	}

	if agg.LastPlatform != "CERNBox" {
		t.Fatalf("last_platform = %q, want CERNBox", agg.LastPlatform)
	}

	if agg.LastHealthy {
		t.Fatal("expected last_healthy false after fail grade")
	}
}

func TestIncrementStatsAggregate_OlderSnapshotDoesNotReplaceMetadata(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()

	pass := GradePass
	fail := GradeFail

	newer := &StatsRaw{
		HostHash:       "hash-order",
		SessionKind:    SessionKindActiveFull,
		Platform:       "CERNBox",
		GradeDiscovery: &fail,
		CreatedAt:      200,
	}

	if err := core.IncrementStatsAggregate(ctx, newer); err != nil {
		t.Fatalf("increment newer: %v", err)
	}

	older := &StatsRaw{
		HostHash:       "hash-order",
		SessionKind:    SessionKindPassiveOnly,
		Platform:       "Nextcloud",
		GradeDiscovery: &pass,
		CreatedAt:      100,
	}

	if err := core.IncrementStatsAggregate(ctx, older); err != nil {
		t.Fatalf("increment older: %v", err)
	}

	var agg StatsAggregate
	if err := core.DB().WithContext(ctx).First(&agg, "host_hash = ?", "hash-order").Error; err != nil {
		t.Fatalf("load aggregate: %v", err)
	}

	if agg.TotalSessions != 2 {
		t.Fatalf("total_sessions = %d, want 2", agg.TotalSessions)
	}

	if agg.HealthySessions != 1 {
		t.Fatalf("healthy_sessions = %d, want 1 from pass-grade older row", agg.HealthySessions)
	}

	if agg.LastPlatform != "CERNBox" {
		t.Fatalf("last_platform = %q, want CERNBox from newer snapshot", agg.LastPlatform)
	}

	if agg.LastHealthy {
		t.Fatal("expected last_healthy false from newer fail-grade snapshot")
	}

	if agg.LastSeenTS != 200 {
		t.Fatalf("last_seen_ts = %d, want 200 from newer snapshot", agg.LastSeenTS)
	}

	if agg.FirstSeenTS != 100 {
		t.Fatalf("first_seen_ts = %d, want 100 from older snapshot", agg.FirstSeenTS)
	}
}

func TestIncrementStatsAggregate_DerivesHealthyFromGrades(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()

	allNull := &StatsRaw{
		HostHash:    "hash-null",
		SessionKind: SessionKindPassiveOnly,
		Platform:    "Unknown",
		CreatedAt:   100,
	}

	if err := core.IncrementStatsAggregate(ctx, allNull); err != nil {
		t.Fatalf("increment all-null: %v", err)
	}

	var nullAgg StatsAggregate
	if err := core.DB().WithContext(ctx).First(&nullAgg, "host_hash = ?", "hash-null").Error; err != nil {
		t.Fatalf("load all-null aggregate: %v", err)
	}

	if nullAgg.HealthySessions != 0 {
		t.Fatalf("all-null healthy_sessions = %d, want 0", nullAgg.HealthySessions)
	}

	if nullAgg.LastHealthy {
		t.Fatal("all-null grades must not set last_healthy true")
	}

	pass := GradePass
	passRaw := &StatsRaw{
		HostHash:       "hash-pass",
		SessionKind:    SessionKindActiveFull,
		Platform:       "Nextcloud",
		GradeDiscovery: &pass,
		CreatedAt:      200,
	}

	if err := core.IncrementStatsAggregate(ctx, passRaw); err != nil {
		t.Fatalf("increment pass: %v", err)
	}

	var passAgg StatsAggregate
	if err := core.DB().WithContext(ctx).First(&passAgg, "host_hash = ?", "hash-pass").Error; err != nil {
		t.Fatalf("load pass aggregate: %v", err)
	}

	if passAgg.HealthySessions != 1 {
		t.Fatalf("pass healthy_sessions = %d, want 1", passAgg.HealthySessions)
	}

	if !passAgg.LastHealthy {
		t.Fatal("pass grade must set last_healthy true")
	}
}

func TestPruneStats_RebuildsAggregateFromRaw(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()

	pass := GradePass
	now := time.Now().Unix()

	rows := []StatsRaw{
		{
			HostHash:       "host-old",
			SessionKind:    SessionKindPassiveOnly,
			Platform:       "Old",
			GradeDiscovery: new(pass),
			CreatedAt:      now - int64(60*24*3600),
		},
		{
			HostHash:       "host-old",
			SessionKind:    SessionKindPassiveOnly,
			Platform:       "Old",
			GradeDiscovery: new(pass),
			CreatedAt:      now - int64(59*24*3600),
		},
		{
			HostHash:       "host-new",
			SessionKind:    SessionKindActiveFull,
			Platform:       "New",
			GradeDiscovery: new(pass),
			CreatedAt:      now - 3600,
		},
	}

	for i := range rows {
		if err := core.InsertStatsRaw(ctx, &rows[i]); err != nil {
			t.Fatalf("insert raw %d: %v", i, err)
		}
	}

	if err := core.PruneStats(ctx, 30); err != nil {
		t.Fatalf("prune: %v", err)
	}

	var aggCount int64
	if err := core.DB().WithContext(ctx).Model(&StatsAggregate{}).Count(&aggCount).Error; err != nil {
		t.Fatalf("count aggregate: %v", err)
	}

	if aggCount != 1 {
		t.Fatalf("aggregate rows = %d, want 1 after prune", aggCount)
	}

	var agg StatsAggregate
	if err := core.DB().WithContext(ctx).First(&agg, "host_hash = ?", "host-new").Error; err != nil {
		t.Fatalf("load rebuilt aggregate: %v", err)
	}

	if agg.TotalSessions != 1 {
		t.Fatalf("rebuilt total_sessions = %d, want 1", agg.TotalSessions)
	}
}

func TestPruneStats_RetentionZeroRebuildsAll(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()

	pass := GradePass

	for _, host := range []string{"host-a", "host-b"} {
		if err := core.InsertStatsRaw(ctx, &StatsRaw{
			HostHash:       host,
			SessionKind:    SessionKindPassiveOnly,
			Platform:       "P",
			GradeDiscovery: new(pass),
			CreatedAt:      1,
		}); err != nil {
			t.Fatalf("insert raw: %v", err)
		}
	}

	if err := core.PruneStats(ctx, 0); err != nil {
		t.Fatalf("prune retention 0: %v", err)
	}

	var rawCount int64
	if err := core.DB().WithContext(ctx).Model(&StatsRaw{}).Count(&rawCount).Error; err != nil {
		t.Fatalf("count raw: %v", err)
	}

	if rawCount != 2 {
		t.Fatalf("raw rows = %d, want 2 when retention_days=0", rawCount)
	}

	var aggCount int64
	if err := core.DB().WithContext(ctx).Model(&StatsAggregate{}).Count(&aggCount).Error; err != nil {
		t.Fatalf("count aggregate: %v", err)
	}

	if aggCount != 2 {
		t.Fatalf("aggregate rows = %d, want 2 after retention 0 rebuild", aggCount)
	}
}

func TestFindActiveCorrelation_ExcludesPending(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()

	runID := "run-1"
	if err := core.DB().WithContext(ctx).Create(&TestRun{
		TestRunID:   runID,
		IsActive:    true,
		State:       StateActiveRunning,
		SessionKind: SessionKindActiveFull,
		TargetHost:  "peer.example",
		CreatedAt:   1,
		UpdatedAt:   1,
	}).Error; err != nil {
		t.Fatalf("create test run: %v", err)
	}

	if err := core.DB().WithContext(ctx).Create(&ShareCorrelation{
		TestRunID:     runID,
		Role:          RoleOutgoingInvite,
		SenderHost:    "peer.example",
		ProviderID:    "token-1",
		LocalIdentity: LocalIdentityA,
		Status:        CorrelationStatusPending,
		CreatedAt:     1,
	}).Error; err != nil {
		t.Fatalf("create pending correlation: %v", err)
	}

	if _, err := core.FindActiveCorrelation(ctx, RoleOutgoingInvite, "peer.example", "token-1"); err == nil {
		t.Fatal("expected pending row to be excluded from FindActiveCorrelation")
	}

	if err := core.DB().WithContext(ctx).Model(&ShareCorrelation{}).
		Where("test_run_id = ?", runID).
		Update("status", CorrelationStatusConfirmed).Error; err != nil {
		t.Fatalf("confirm correlation: %v", err)
	}

	got, err := core.FindActiveCorrelation(ctx, RoleOutgoingInvite, "peer.example", "token-1")
	if err != nil {
		t.Fatalf("FindActiveCorrelation confirmed: %v", err)
	}

	if got != runID {
		t.Fatalf("test_run_id = %q, want %q", got, runID)
	}
}

func TestFindCorrelationAnyStatus_IncludesPending(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()

	runID := "run-pending"
	if err := core.DB().WithContext(ctx).Create(&TestRun{
		TestRunID:   runID,
		IsActive:    true,
		State:       StateActiveRunning,
		SessionKind: SessionKindActiveFull,
		TargetHost:  "peer.example",
		CreatedAt:   1,
		UpdatedAt:   1,
	}).Error; err != nil {
		t.Fatalf("create test run: %v", err)
	}

	if err := core.DB().WithContext(ctx).Create(&ShareCorrelation{
		TestRunID:     runID,
		Role:          RoleOutgoingInvite,
		SenderHost:    "peer.example",
		ProviderID:    "token-pending",
		LocalIdentity: LocalIdentityA,
		Status:        CorrelationStatusPending,
		CreatedAt:     1,
	}).Error; err != nil {
		t.Fatalf("create pending correlation: %v", err)
	}

	got, err := core.FindCorrelationAnyStatus(ctx, RoleOutgoingInvite, "peer.example", "token-pending")
	if err != nil {
		t.Fatalf("FindCorrelationAnyStatus: %v", err)
	}

	if got != runID {
		t.Fatalf("test_run_id = %q, want %q", got, runID)
	}
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

func TestPruneStats_RebuildMatchesIncrementalAggregate(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()

	pass := GradePass
	fail := GradeFail
	hostHash := "hash-rebuild-parity"

	newer := &StatsRaw{
		HostHash:       hostHash,
		SessionKind:    SessionKindActiveFull,
		Platform:       "CERNBox",
		GradeDiscovery: &fail,
		CreatedAt:      200,
	}

	older := &StatsRaw{
		HostHash:       hostHash,
		SessionKind:    SessionKindPassiveOnly,
		Platform:       "Nextcloud",
		GradeDiscovery: &pass,
		CreatedAt:      100,
	}

	for _, raw := range []*StatsRaw{newer, older} {
		if err := core.InsertStatsRaw(ctx, raw); err != nil {
			t.Fatalf("insert raw: %v", err)
		}
	}

	if err := core.IncrementStatsAggregate(ctx, newer); err != nil {
		t.Fatalf("increment newer: %v", err)
	}

	if err := core.IncrementStatsAggregate(ctx, older); err != nil {
		t.Fatalf("increment older: %v", err)
	}

	var incremental StatsAggregate
	if err := core.DB().WithContext(ctx).First(&incremental, "host_hash = ?", hostHash).Error; err != nil {
		t.Fatalf("load incremental aggregate: %v", err)
	}

	if incremental.TotalSessions != 2 {
		t.Fatalf("incremental total_sessions = %d, want 2", incremental.TotalSessions)
	}

	if incremental.HealthySessions != 1 {
		t.Fatalf("incremental healthy_sessions = %d, want 1", incremental.HealthySessions)
	}

	if incremental.FirstSeenTS != 100 {
		t.Fatalf("incremental first_seen_ts = %d, want 100", incremental.FirstSeenTS)
	}

	if incremental.LastSeenTS != 200 {
		t.Fatalf("incremental last_seen_ts = %d, want 200", incremental.LastSeenTS)
	}

	if incremental.LastPlatform != "CERNBox" {
		t.Fatalf("incremental last_platform = %q, want CERNBox", incremental.LastPlatform)
	}

	if incremental.LastHealthy {
		t.Fatal("incremental last_healthy = true, want false from newer fail grade")
	}

	if err := core.PruneStats(ctx, 0); err != nil {
		t.Fatalf("prune retention 0: %v", err)
	}

	var rebuilt StatsAggregate
	if err := core.DB().WithContext(ctx).First(&rebuilt, "host_hash = ?", hostHash).Error; err != nil {
		t.Fatalf("load rebuilt aggregate: %v", err)
	}

	assertStatsAggregateContract(t, incremental, rebuilt)
}

func assertStatsAggregateContract(t *testing.T, got, want StatsAggregate) {
	t.Helper()

	if got.TotalSessions != want.TotalSessions {
		t.Fatalf("total_sessions = %d, want %d", got.TotalSessions, want.TotalSessions)
	}

	if got.HealthySessions != want.HealthySessions {
		t.Fatalf("healthy_sessions = %d, want %d", got.HealthySessions, want.HealthySessions)
	}

	if got.FirstSeenTS != want.FirstSeenTS {
		t.Fatalf("first_seen_ts = %d, want %d", got.FirstSeenTS, want.FirstSeenTS)
	}

	if got.LastSeenTS != want.LastSeenTS {
		t.Fatalf("last_seen_ts = %d, want %d", got.LastSeenTS, want.LastSeenTS)
	}

	if got.LastPlatform != want.LastPlatform {
		t.Fatalf("last_platform = %q, want %q", got.LastPlatform, want.LastPlatform)
	}

	if got.LastHealthy != want.LastHealthy {
		t.Fatalf("last_healthy = %v, want %v", got.LastHealthy, want.LastHealthy)
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

func TestDeriveHealthy_AllNullNotHealthy(t *testing.T) {
	t.Parallel()

	if DeriveHealthy(StatsRaw{}) {
		t.Fatal("all-NULL grades must not be healthy")
	}
}

func TestDeriveHealthy_WarnNotHealthy(t *testing.T) {
	t.Parallel()

	warn := GradeWarn
	if DeriveHealthy(StatsRaw{GradeDiscovery: &warn}) {
		t.Fatal("warn grade must not be healthy")
	}
}
