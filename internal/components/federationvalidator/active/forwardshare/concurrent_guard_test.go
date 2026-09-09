// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package forwardshare_test

import (
	"errors"
	"sync"
	"testing"
	"time"

	outgoingshares "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api/outgoing/shares"
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

func TestConcurrentGuard_RekeysPerParty(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t, true)
	ctx := t.Context()
	otherHost := "other.example"

	env.seedActiveRun(t, "run-alpha", validatorcore.StateReverseInviteAccepted)
	seedActiveRunOn(t, env, "run-beta", otherHost, validatorcore.StateReverseInviteAccepted)

	reqA := designatedRequest(env)
	reqB := sharesoutgoing.OutgoingShareRequest{
		ReceiverDomain: otherHost,
		ShareWith:      testDesignated + "@" + otherHost,
		LocalPath:      env.probePath,
		Permissions:    []string{"read"},
	}

	var (
		wg      sync.WaitGroup
		start   = make(chan struct{})
		planA   *outgoingshares.DispatchPlan
		planB   *outgoingshares.DispatchPlan
		errA    error
		errB    error
		miss    *outgoingshares.DispatchPlan
		missErr error
	)

	wg.Add(3)

	go func() {
		defer wg.Done()

		<-start

		planA, errA = env.svc.GuardCreate(ctx, reqA, "run-alpha")
	}()
	go func() {
		defer wg.Done()

		<-start

		planB, errB = env.svc.GuardCreate(ctx, reqB, "run-beta")
	}()
	go func() {
		defer wg.Done()

		<-start

		miss, missErr = env.svc.GuardCreate(ctx, reqA, "user-nobody")
	}()

	close(start)
	wg.Wait()

	if errA != nil {
		t.Fatalf("GuardCreate alpha: %v", errA)
	}

	if errB != nil {
		t.Fatalf("GuardCreate beta: %v", errB)
	}

	if missErr != nil {
		t.Fatalf("GuardCreate miss: %v", missErr)
	}

	if planA == nil || planA.TestRunID != "run-alpha" {
		t.Fatalf("alpha plan = %+v, want run-alpha", planA)
	}

	if planB == nil || planB.TestRunID != "run-beta" {
		t.Fatalf("beta plan = %+v, want run-beta", planB)
	}

	if planA.ProviderID == "" || planA.ProviderID == planB.ProviderID {
		t.Fatalf("provider ids = %q, %q, want distinct minted ids", planA.ProviderID, planB.ProviderID)
	}

	if miss != nil {
		t.Fatalf("party miss returned plan %+v, want nil skip", miss)
	}

	resA := env.requireReservation(t, "run-alpha")
	resB := env.requireReservation(t, "run-beta")

	if resA.ProviderID != planA.ProviderID || resB.ProviderID != planB.ProviderID {
		t.Fatalf("reservation providers = %q, %q, want %q, %q", resA.ProviderID, resB.ProviderID, planA.ProviderID, planB.ProviderID)
	}

	if _, err := env.store.GetDispatchReservation(ctx, "user-nobody"); !errors.Is(err, validatorcore.ErrDispatchReservationNotFound) {
		t.Fatalf("GetDispatchReservation(user-nobody) = %v, want ErrDispatchReservationNotFound", err)
	}

	env.requireState(t, "run-alpha", validatorcore.StateReverseInviteAccepted)
	env.requireState(t, "run-beta", validatorcore.StateReverseInviteAccepted)
}

func TestConcurrentGuard_SamePartySerializesReserve(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t, true)
	ctx := t.Context()
	runID := "run-same-party"

	env.seedActiveRun(t, runID, validatorcore.StateReverseInviteAccepted)

	req := designatedRequest(env)

	var wg sync.WaitGroup

	start := make(chan struct{})
	plans := make(chan *outgoingshares.DispatchPlan, 2)
	errs := make(chan error, 2)

	wg.Add(2)

	for range 2 {
		go func() {
			defer wg.Done()

			<-start

			plan, err := env.svc.GuardCreate(ctx, req, runID)
			if err != nil {
				errs <- err

				return
			}

			plans <- plan
		}()
	}

	close(start)
	wg.Wait()
	close(plans)
	close(errs)

	var (
		successes  int
		inProgress int
	)

	for err := range errs {
		if errors.Is(err, outgoingshares.ErrDispatchInProgress) {
			inProgress++

			continue
		}

		if errors.Is(err, outgoingshares.ErrDispatchRefused) {
			t.Fatal("same-party loser returned ErrDispatchRefused, want ErrDispatchInProgress")
		}

		t.Fatalf("GuardCreate: %v", err)
	}

	seen := map[string]struct{}{}

	for plan := range plans {
		if plan == nil || plan.TestRunID != runID {
			t.Fatalf("plan = %+v, want %s", plan, runID)
		}

		seen[plan.ProviderID] = struct{}{}
		successes++
	}

	if successes != 1 {
		t.Fatalf("successful plans = %d, want 1", successes)
	}

	if inProgress != 1 {
		t.Fatalf("ErrDispatchInProgress outcomes = %d, want 1", inProgress)
	}

	if len(seen) != 1 {
		t.Fatalf("provider ids = %v, want one reserved identity", seen)
	}

	reservation := env.requireReservation(t, runID)
	if _, ok := seen[reservation.ProviderID]; !ok {
		t.Fatalf("reservation provider %q not in granted plans %v", reservation.ProviderID, seen)
	}
}

func seedActiveRunOn(t *testing.T, env *testEnv, runID, host, state string) {
	t.Helper()

	now := time.Now().Unix()
	designated := testDesignated

	if err := env.store.DB().WithContext(t.Context()).Create(&validatorcore.TestRun{
		TestRunID:           runID,
		IsActive:            true,
		State:               state,
		TargetHost:          host,
		DesignatedShareWith: &designated,
		CreatedAt:           now,
		UpdatedAt:           now,
	}).Error; err != nil {
		t.Fatalf("seed run %s: %v", runID, err)
	}
}
