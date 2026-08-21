// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestFindActiveCorrelation_ExcludesPending(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-1"

	seedActiveRun(t, core, runID, "peer.example", true)
	seedCorrelation(t, core, ShareCorrelation{
		TestRunID:     runID,
		Role:          RoleOutgoingInvite,
		SenderHost:    "peer.example",
		ProviderID:    "token-1",
		LocalIdentity: LocalIdentityA,
		Status:        CorrelationStatusPending,
		CreatedAt:     1,
	})

	if _, err := core.FindActiveCorrelation(
		ctx,
		RoleOutgoingInvite,
		"peer.example",
		"token-1",
		LocalIdentityA,
	); err == nil {
		t.Fatal("expected pending row to be excluded from FindActiveCorrelation")
	}

	if err := core.DB().WithContext(ctx).Model(&ShareCorrelation{}).
		Where("test_run_id = ?", runID).
		Update("status", CorrelationStatusConfirmed).Error; err != nil {
		t.Fatalf("confirm correlation: %v", err)
	}

	got, err := core.FindActiveCorrelation(
		ctx,
		RoleOutgoingInvite,
		"peer.example",
		"token-1",
		LocalIdentityA,
	)
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

	seedActiveRun(t, core, runID, "peer.example", true)
	seedCorrelation(t, core, ShareCorrelation{
		TestRunID:     runID,
		Role:          RoleOutgoingInvite,
		SenderHost:    "peer.example",
		ProviderID:    "token-pending",
		LocalIdentity: LocalIdentityA,
		Status:        CorrelationStatusPending,
		CreatedAt:     1,
	})

	got, err := core.FindCorrelationAnyStatus(
		ctx,
		RoleOutgoingInvite,
		"peer.example",
		"token-pending",
		LocalIdentityA,
	)
	if err != nil {
		t.Fatalf("FindCorrelationAnyStatus: %v", err)
	}

	if got != runID {
		t.Fatalf("test_run_id = %q, want %q", got, runID)
	}
}

func TestFinders_AAndBOccupancySameTuple(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-occupancy"

	seedActiveRun(t, core, runID, "identity.example", true)

	base := ShareCorrelation{
		TestRunID:  runID,
		Role:       RoleOutgoingToTarget,
		SenderHost: "identity.example",
		ProviderID: "share-identity-1",
		Status:     CorrelationStatusConfirmed,
		CreatedAt:  1,
	}

	rowA := base
	rowA.LocalIdentity = LocalIdentityA
	seedCorrelation(t, core, rowA)

	rowB := base
	rowB.LocalIdentity = LocalIdentityB
	rowB.CreatedAt = 2
	seedCorrelation(t, core, rowB)

	gotA, err := core.FindActiveCorrelation(
		ctx,
		RoleOutgoingToTarget,
		"identity.example",
		"share-identity-1",
		LocalIdentityA,
	)
	if err != nil {
		t.Fatalf("FindActiveCorrelation a: %v", err)
	}

	gotB, err := core.FindActiveCorrelation(
		ctx,
		RoleOutgoingToTarget,
		"identity.example",
		"share-identity-1",
		LocalIdentityB,
	)
	if err != nil {
		t.Fatalf("FindActiveCorrelation b: %v", err)
	}

	if gotA != runID || gotB != runID {
		t.Fatalf("occupancy run ids = %q, %q, want %q", gotA, gotB, runID)
	}

	var count int64
	if err := core.DB().WithContext(ctx).Model(&ShareCorrelation{}).
		Where(
			"test_run_id = ? AND role = ? AND sender_host = ? AND provider_id = ?",
			runID,
			RoleOutgoingToTarget,
			"identity.example",
			"share-identity-1",
		).Count(&count).Error; err != nil {
		t.Fatalf("count occupancy rows: %v", err)
	}

	if count != 2 {
		t.Fatalf("occupancy rows = %d, want 2", count)
	}
}

func TestFinders_InvalidLocalIdentityDoesNotQuery(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		identity     string
		unconfigured bool
	}{
		{name: "empty", identity: ""},
		{name: "unknown", identity: "c"},
		{name: "uppercase a", identity: "A"},
		{name: "unconfigured empty", identity: "", unconfigured: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			core := openTestCore(t)
			ctx := t.Context()
			count := attachQueryCounter(core)

			if tt.unconfigured {
				core = &Core{}
			}

			before := count.Load()

			if _, err := core.FindOneActive(ctx, tt.identity); !errors.Is(err, ErrInvalidLocalIdentity) {
				t.Fatalf("FindOneActive: %v, want ErrInvalidLocalIdentity", err)
			}

			if _, err := core.FindActiveCorrelation(
				ctx,
				RoleOutgoingInvite,
				"peer.example",
				"token-1",
				tt.identity,
			); !errors.Is(err, ErrInvalidLocalIdentity) {
				t.Fatalf("FindActiveCorrelation: %v, want ErrInvalidLocalIdentity", err)
			}

			if _, err := core.FindCorrelationAnyStatus(
				ctx,
				RoleOutgoingInvite,
				"peer.example",
				"token-1",
				tt.identity,
			); !errors.Is(err, ErrInvalidLocalIdentity) {
				t.Fatalf("FindCorrelationAnyStatus: %v, want ErrInvalidLocalIdentity", err)
			}

			if got := count.Load() - before; got != 0 {
				t.Fatalf("queries = %d, want 0", got)
			}
		})
	}
}

func TestFinders_QueryCounterObservesFindOneActive(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	count := attachQueryCounter(core)
	seedActiveRun(t, core, "run-query-probe", "peer.example", true)

	beforeProbe := count.Load()

	if _, err := core.FindOneActive(ctx, LocalIdentityA); err != nil {
		t.Fatalf("FindOneActive probe: %v", err)
	}

	if count.Load() == beforeProbe {
		t.Fatal("query counter did not observe FindOneActive")
	}
}

func TestFindOneActive_AliceAndBobBinding(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-one-active"

	seedActiveRun(t, core, runID, "peer.example", true)

	gotA, err := core.FindOneActive(ctx, LocalIdentityA)
	if err != nil {
		t.Fatalf("FindOneActive a: %v", err)
	}

	if gotA != runID {
		t.Fatalf("FindOneActive a = %q, want %q", gotA, runID)
	}

	if _, errB := core.FindOneActive(ctx, LocalIdentityB); !errors.Is(errB, gorm.ErrRecordNotFound) {
		t.Fatalf("FindOneActive b with null bob_user_id: %v, want ErrRecordNotFound", errB)
	}

	bobUserID := "bob-user-1"
	if updateErr := core.DB().WithContext(ctx).Model(&TestRun{}).
		Where("test_run_id = ?", runID).
		Update("bob_user_id", bobUserID).Error; updateErr != nil {
		t.Fatalf("set bob_user_id: %v", updateErr)
	}

	gotB, err := core.FindOneActive(ctx, LocalIdentityB)
	if err != nil {
		t.Fatalf("FindOneActive b after bob_user_id: %v", err)
	}

	if gotB != runID {
		t.Fatalf("FindOneActive b = %q, want %q", gotB, runID)
	}
}

func TestFindOneActive_InactiveAndMissingNotFound(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()

	if _, err := core.FindOneActive(ctx, LocalIdentityA); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("missing active run: %v, want ErrRecordNotFound", err)
	}

	seedActiveRun(t, core, "run-inactive", "peer.example", false)

	if _, err := core.FindOneActive(ctx, LocalIdentityA); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("inactive run: %v, want ErrRecordNotFound", err)
	}
}

func TestFinders_AmbiguousCardinalityNotFound(t *testing.T) {
	t.Parallel()

	t.Run("two active runs", func(t *testing.T) {
		t.Parallel()

		core := openTestCore(t)
		ctx := t.Context()

		mustExec(t, core.DB(), "DROP INDEX idx_test_run_one_active")
		seedActiveRun(t, core, "run-active-1", "peer.example", true)
		seedActiveRun(t, core, "run-active-2", "peer.example", true)

		if _, err := core.FindOneActive(ctx, LocalIdentityA); !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("FindOneActive ambiguous: %v, want ErrRecordNotFound", err)
		}
	})

	t.Run("two confirmed correlations", func(t *testing.T) {
		t.Parallel()

		core := openTestCore(t)
		ctx := t.Context()
		runID := "run-ambiguous-corr"

		seedActiveRun(t, core, runID, "peer.example", true)
		mustExec(t, core.DB(), "DROP INDEX idx_share_corr_unique")

		row := ShareCorrelation{
			TestRunID:     runID,
			Role:          RoleOutgoingToTarget,
			SenderHost:    "peer.example",
			ProviderID:    "share-ambiguous",
			LocalIdentity: LocalIdentityA,
			Status:        CorrelationStatusConfirmed,
			CreatedAt:     1,
		}
		seedCorrelation(t, core, row)

		row.CreatedAt = 2
		seedCorrelation(t, core, row)

		if _, err := core.FindActiveCorrelation(
			ctx,
			RoleOutgoingToTarget,
			"peer.example",
			"share-ambiguous",
			LocalIdentityA,
		); !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("FindActiveCorrelation ambiguous: %v, want ErrRecordNotFound", err)
		}

		if _, err := core.FindCorrelationAnyStatus(
			ctx,
			RoleOutgoingToTarget,
			"peer.example",
			"share-ambiguous",
			LocalIdentityA,
		); !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("FindCorrelationAnyStatus ambiguous: %v, want ErrRecordNotFound", err)
		}
	})
}

func seedActiveRun(t *testing.T, core *Core, runID, host string, active bool) {
	t.Helper()

	if err := core.DB().WithContext(t.Context()).Create(&TestRun{
		TestRunID:  runID,
		IsActive:   active,
		State:      StateActiveRunning,
		TargetHost: host,
		CreatedAt:  1,
		UpdatedAt:  1,
	}).Error; err != nil {
		t.Fatalf("create test run: %v", err)
	}
}

func seedCorrelation(t *testing.T, core *Core, row ShareCorrelation) {
	t.Helper()

	if err := core.DB().WithContext(t.Context()).Create(&row).Error; err != nil {
		t.Fatalf("create correlation: %v", err)
	}
}

func attachQueryCounter(core *Core) *atomic.Int64 {
	count := &atomic.Int64{}
	queryLogger := &queryCountLogger{count: count}
	db := core.DB()
	db.Logger = queryLogger

	return count
}

type queryCountLogger struct {
	count *atomic.Int64
}

func (l *queryCountLogger) LogMode(logger.LogLevel) logger.Interface {
	return l
}

func (l *queryCountLogger) Info(context.Context, string, ...any) {}

func (l *queryCountLogger) Warn(context.Context, string, ...any) {}

func (l *queryCountLogger) Error(context.Context, string, ...any) {}

func (l *queryCountLogger) Trace(
	_ context.Context,
	_ time.Time,
	_ func() (sql string, rowsAffected int64),
	_ error,
) {
	l.count.Add(1)
}
