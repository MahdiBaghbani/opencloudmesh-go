// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package forwardshare_test

import (
	"encoding/json"
	"net/http"
	"sync"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

func TestDispatch_DesignatedShareSentAndCommitted(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t, true)
	env.seedActiveRun(t, "run-dispatch", validatorcore.StateReverseInviteAccepted)

	w := env.doCreate(t, env.designatedBody())
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", w.Code, w.Body.String())
	}

	if got := env.postCount.Load(); got != 1 {
		t.Fatalf("outbound POSTs = %d, want 1", got)
	}

	env.requireState(t, "run-dispatch", validatorcore.StateForwardShareSent)

	reservation := env.requireReservation(t, "run-dispatch")
	if reservation.Status != validatorcore.DispatchStatusCASCommitted {
		t.Fatalf("reservation status = %q, want %q", reservation.Status, validatorcore.DispatchStatusCASCommitted)
	}

	if reservation.CASCommittedAt == nil {
		t.Fatal("reservation commit not stamped")
	}

	shares := env.listShares(t)
	if len(shares) != 1 {
		t.Fatalf("stored shares = %d, want 1", len(shares))
	}

	// The dispatched share reuses the reserved provider identity, and the
	// wire payload carries it with the snapshotted WebDAV identity.
	if shares[0].ProviderID != reservation.ProviderID {
		t.Fatalf("share provider id = %q, want reserved %q", shares[0].ProviderID, reservation.ProviderID)
	}

	payloads := env.captured.all()
	if len(payloads) != 1 {
		t.Fatalf("captured payloads = %d, want 1", len(payloads))
	}

	if payloads[0].ProviderID != reservation.ProviderID {
		t.Fatalf("wire provider id = %q, want reserved %q", payloads[0].ProviderID, reservation.ProviderID)
	}

	if payloads[0].Protocol.WebDAV == nil || payloads[0].Protocol.WebDAV.SharedSecret != reservation.SharedSecret {
		t.Fatal("wire shared secret does not match the reservation snapshot")
	}
}

func TestDispatch_ConcurrentSecondInsertRejectedPreSend(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t, true)
	env.seedActiveRun(t, "run-dispatch-race", validatorcore.StateReverseInviteAccepted)

	const racers = 8

	var wg sync.WaitGroup

	codes := make(chan int, racers)

	for range racers {
		wg.Add(1)

		go func() {
			defer wg.Done()

			w := env.doCreate(t, env.designatedBody())
			codes <- w.Code
		}()
	}

	wg.Wait()
	close(codes)

	created := 0

	for code := range codes {
		switch code {
		case http.StatusCreated:
			created++
		case http.StatusConflict, http.StatusForbidden:
			// Losers of the single-winner race refuse before sending.
		default:
			t.Fatalf("unexpected status %d", code)
		}
	}

	if created == 0 {
		t.Fatal("no dispatcher succeeded")
	}

	// Exactly one designated remote share, one local row, one reservation.
	if got := env.postCount.Load(); got != 1 {
		t.Fatalf("outbound POSTs = %d, want 1", got)
	}

	shares := env.listShares(t)
	if len(shares) != 1 {
		t.Fatalf("stored shares = %d, want 1", len(shares))
	}

	reservation := env.requireReservation(t, "run-dispatch-race")
	if shares[0].ProviderID != reservation.ProviderID {
		t.Fatalf("share provider id = %q, want reserved %q", shares[0].ProviderID, reservation.ProviderID)
	}

	env.requireState(t, "run-dispatch-race", validatorcore.StateForwardShareSent)
}

func TestDispatch_ReplayAfterCrashBeforeCommitReconciles(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t, true)
	env.seedActiveRun(t, "run-dispatch-crash", validatorcore.StateReverseInviteAccepted)

	// First attempt: the send permit is taken and the remote send is
	// recorded, but the commit never lands, simulating a crash between the
	// outbound POST and the commit CAS.
	plan, err := env.svc.GuardCreate(t.Context(), designatedRequest(env), "run-dispatch-crash")
	if err != nil {
		t.Fatalf("guard: %v", err)
	}

	if plan == nil || plan.ReplayShare != nil {
		t.Fatalf("plan = %+v, want a fresh dispatch plan", plan)
	}

	env.persistDispatchedShare(t, plan)

	if err := env.store.MarkForwardDispatchRemoteSent(t.Context(), "run-dispatch-crash", plan.ProviderID, plan.ClaimToken, ""); err != nil {
		t.Fatalf("mark remote sent: %v", err)
	}

	// The retry reconciles without a second outbound POST and reuses the
	// reserved provider identity.
	w := env.doCreate(t, env.designatedBody())
	if w.Code != http.StatusCreated {
		t.Fatalf("replay status = %d, want 201: %s", w.Code, w.Body.String())
	}

	if got := env.postCount.Load(); got != 0 {
		t.Fatalf("outbound POSTs = %d, want none on replay", got)
	}

	env.requireState(t, "run-dispatch-crash", validatorcore.StateForwardShareSent)

	reservation := env.requireReservation(t, "run-dispatch-crash")
	if reservation.CASCommittedAt == nil {
		t.Fatal("reservation commit not stamped by replay")
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode replay response: %v", err)
	}

	if resp["providerId"] != plan.ProviderID {
		t.Fatalf("replay provider id = %q, want reserved %q", resp["providerId"], plan.ProviderID)
	}
}

func TestDispatch_ReplayHealsCapabilityAdvanceBeforeResponding(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t, true)
	env.seedActiveRun(t, "run-dispatch-heal", validatorcore.StateReverseInviteAccepted)

	w := env.doCreate(t, env.designatedBody())
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", w.Code, w.Body.String())
	}

	env.requireState(t, "run-dispatch-heal", validatorcore.StateForwardShareSent)

	// The capability observation lands after the commit, so its evidence row
	// exists but the insert-gated advance inside the evidence seam can never
	// fire for it. The replay must heal the advance before answering.
	env.seedCapabilityEvidence(t, "run-dispatch-heal", "webdav_get")

	w = env.doCreate(t, env.designatedBody())
	if w.Code != http.StatusCreated {
		t.Fatalf("replay status = %d, want 201: %s", w.Code, w.Body.String())
	}

	// The heal ran before the 201 response was written.
	env.requireState(t, "run-dispatch-heal", validatorcore.StateCapabilityExercise)

	if got := env.postCount.Load(); got != 1 {
		t.Fatalf("outbound POSTs = %d, want 1", got)
	}
}

func TestDispatch_RecordedSendThenStallInterruptsThroughSharedWriter(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t, true)
	env.seedActiveRun(t, "run-dispatch-stall", validatorcore.StateReverseInviteAccepted)

	plan, err := env.svc.GuardCreate(t.Context(), designatedRequest(env), "run-dispatch-stall")
	if err != nil {
		t.Fatalf("guard: %v", err)
	}

	env.persistDispatchedShare(t, plan)

	if markErr := env.store.MarkForwardDispatchRemoteSent(t.Context(), "run-dispatch-stall", plan.ProviderID, plan.ClaimToken, ""); markErr != nil {
		t.Fatalf("mark remote sent: %v", markErr)
	}

	// Another writer moves the run backwards before the commit can land, so
	// the commit CAS can never succeed for this recorded send.
	env.setRunState(t, "run-dispatch-stall", validatorcore.StateInviteMinted)

	w := env.doCreate(t, env.designatedBody())
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", w.Code, w.Body.String())
	}

	// The run is interrupted through the shared active-terminal writer, never
	// failed, and the reservation facts survive for reconciliation.
	env.requireState(t, "run-dispatch-stall", validatorcore.StateInterrupted)

	run, err := env.store.GetTestRun(t.Context(), "run-dispatch-stall")
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if run.TerminalReason == nil || *run.TerminalReason == "" {
		t.Fatal("terminal reason not recorded")
	}

	reservation := env.requireReservation(t, "run-dispatch-stall")
	if reservation.Status != validatorcore.DispatchStatusRemoteSent {
		t.Fatalf("reservation status = %q, want %q", reservation.Status, validatorcore.DispatchStatusRemoteSent)
	}

	// The interrupted run is no longer active, so the reservation facts are
	// retained but the guard no longer applies to new requests.
	if got := env.postCount.Load(); got != 0 {
		t.Fatalf("outbound POSTs = %d, want none", got)
	}
}
