// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"errors"
	"testing"

	"gorm.io/gorm"
)

func TestFindActiveCorrelation_ExcludesPending(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-1"

	seedActiveRun(t, core, runID, "peer.example", true)
	seedCorrelation(t, core, ShareCorrelation{
		TestRunID:     runID,
		Role:          RoleOutgoingToTarget,
		SenderHost:    "peer.example",
		ProviderID:    "token-1",
		LocalIdentity: LocalIdentityA,
		Status:        CorrelationStatusPending,
		CreatedAt:     1,
	})

	if _, err := core.FindActiveCorrelation(
		ctx,
		RoleOutgoingToTarget,
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
		RoleOutgoingToTarget,
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
		Role:          RoleOutgoingToTarget,
		SenderHost:    "peer.example",
		ProviderID:    "token-pending",
		LocalIdentity: LocalIdentityA,
		Status:        CorrelationStatusPending,
		CreatedAt:     1,
	})

	got, err := core.FindCorrelationAnyStatus(
		ctx,
		RoleOutgoingToTarget,
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

func TestFinders_AmbiguousCardinalityNotFound(t *testing.T) {
	t.Parallel()

	t.Run("two active runs", func(t *testing.T) {
		t.Parallel()

		core := openTestCore(t)
		ctx := t.Context()

		mustExec(t, core.DB(), "DROP INDEX idx_test_run_active_per_target")
		seedActiveRun(t, core, "run-active-1", "peer.example", true)
		seedActiveRun(t, core, "run-active-2", "peer.example", true)

		if _, err := core.FindActiveByTarget(ctx, "peer.example"); !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("FindActiveByTarget ambiguous: %v, want ErrRecordNotFound", err)
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
