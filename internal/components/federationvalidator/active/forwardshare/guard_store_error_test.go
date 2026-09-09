// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package forwardshare_test

import (
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"gorm.io/gorm"

	outgoingshares "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api/outgoing/shares"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

func TestGuard_UnexpectedClaimErrorIsPropagated(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t, true)
	ctx := t.Context()
	runID := "run-guard-claim-store-err"

	env.seedActiveRun(t, runID, validatorcore.StateReverseInviteAccepted)

	injected := failNextDispatchReservationUpdate(t, env.store)
	plan, err := env.svc.GuardCreate(ctx, designatedRequest(env), runID)

	if plan != nil {
		t.Fatalf("plan = %+v, want nil after unexpected claim error", plan)
	}

	if errors.Is(err, outgoingshares.ErrDispatchInProgress) {
		t.Fatal("unexpected claim error mapped to ErrDispatchInProgress")
	}

	if !errors.Is(err, injected) {
		t.Fatalf("GuardCreate error = %v, want wrapped %v", err, injected)
	}

	reservation := env.requireReservation(t, runID)
	if reservation.Status != validatorcore.DispatchStatusReserved {
		t.Fatalf("reservation status = %q, want reserved after failed claim", reservation.Status)
	}

	env.requireState(t, runID, validatorcore.StateReverseInviteAccepted)
}

func TestGuard_UnexpectedReclaimErrorIsPropagated(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t, true)
	ctx := t.Context()
	runID := "run-guard-reclaim-store-err"
	providerID := "prov-reclaim-store-err"
	claimToken := "tok-reclaim-observed"

	env.seedActiveRun(t, runID, validatorcore.StateReverseInviteAccepted)

	if err := env.store.ReserveForwardDispatch(ctx, validatorcore.ForwardDispatchReservation{
		TestRunID:           runID,
		ProviderID:          providerID,
		WebDAVID:            "webdav-" + providerID,
		SharedSecret:        "secret-" + providerID,
		ReceiverHost:        env.targetHost,
		ShareWith:           testDesignated + "@" + env.targetHost,
		DesignatedShareWith: testDesignated,
		ProbeFilePath:       filepath.Clean(env.probePath),
	}); err != nil {
		t.Fatalf("ReserveForwardDispatch: %v", err)
	}

	if err := env.store.ClaimForwardDispatchSend(ctx, runID, providerID, claimToken); err != nil {
		t.Fatalf("ClaimForwardDispatchSend: %v", err)
	}

	env.ageReservation(t, runID, 60)

	injected := failNextDispatchReservationUpdate(t, env.store)
	plan, err := env.svc.GuardCreate(ctx, designatedRequest(env), runID)

	if plan != nil {
		t.Fatalf("plan = %+v, want nil after unexpected reclaim error", plan)
	}

	if errors.Is(err, outgoingshares.ErrDispatchInProgress) {
		t.Fatal("unexpected reclaim error mapped to ErrDispatchInProgress")
	}

	if !errors.Is(err, injected) {
		t.Fatalf("GuardCreate error = %v, want wrapped %v", err, injected)
	}

	reservation := env.requireReservation(t, runID)
	if reservation.Status != validatorcore.DispatchStatusClaimed {
		t.Fatalf("reservation status = %q, want claimed after failed reclaim", reservation.Status)
	}

	env.requireState(t, runID, validatorcore.StateReverseInviteAccepted)
}

func failNextDispatchReservationUpdate(t *testing.T, store *validatorcore.Core) error {
	t.Helper()

	injected := errors.New("injected dispatch reservation store failure")

	const cbName = "test_fail_dispatch_reservation_update"

	var once sync.Once

	if err := store.DB().Callback().Update().Before("gorm:update").Register(cbName, func(db *gorm.DB) {
		if db.Statement.Table != "dispatch_reservation" {
			return
		}

		once.Do(func() {
			if addErr := db.AddError(injected); !errors.Is(addErr, injected) {
				t.Errorf("inject dispatch reservation update failure: got %v", addErr)
			}
		})
	}); err != nil {
		t.Fatalf("register callback: %v", err)
	}

	t.Cleanup(func() {
		if err := store.DB().Callback().Update().Remove(cbName); err != nil {
			t.Errorf("remove callback: %v", err)
		}
	})

	return injected
}
