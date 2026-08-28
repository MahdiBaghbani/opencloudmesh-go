// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package forwardshare_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	outgoingshares "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api/outgoing/shares"
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

// commitGateHook delegates every seat to the real dispatch service but holds
// CommitSent open until the test releases it, so the client request can be
// canceled deterministically while the commit is in flight.
type commitGateHook struct {
	outgoingshares.DispatchHook

	entered chan struct{}
	proceed chan struct{}
}

func (g *commitGateHook) CommitSent(ctx context.Context, plan *outgoingshares.DispatchPlan, share *sharesoutgoing.OutgoingShare) error {
	close(g.entered)
	<-g.proceed

	if err := g.DispatchHook.CommitSent(ctx, plan, share); err != nil {
		return fmt.Errorf("commit gate: %w", err)
	}

	return nil
}

// A client request canceled while the receiver POST is in flight leaves the
// send permit claimed only until the handler's deferred release runs with a
// detached context. The retry then reuses the same provider identity and
// completes with exactly one remote share.
func TestDispatch_CanceledRequestReleasesPermitForRetry(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t, true)
	env.seedActiveRun(t, "run-dispatch-cancel", validatorcore.StateReverseInviteAccepted)

	env.blockPosts.Store(true)

	ctx, cancel := context.WithCancel(t.Context())
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/api/shares/outgoing", bytes.NewBufferString(env.designatedBody()))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	done := make(chan struct{})

	go func() {
		defer close(done)

		env.handler.HandleCreate(w, req)
	}()

	// The live handler claimed the send permit and the outbound POST is in
	// flight; nothing is recorded at the receiver yet.
	select {
	case <-env.postEntered:
	case <-time.After(10 * time.Second):
		t.Fatal("receiver never saw the outbound POST")
	}

	reservation := env.requireReservation(t, "run-dispatch-cancel")
	if reservation.Status != validatorcore.DispatchStatusClaimed {
		t.Fatalf("status while send in flight = %q, want %q", reservation.Status, validatorcore.DispatchStatusClaimed)
	}

	// The client goes away mid-send, the crash/cancellation window before
	// the remote send is recorded.
	cancel()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("handler did not return after request cancellation")
	}

	env.blockPosts.Store(false)

	// Unblock the receiver goroutine; the client is already gone, so its
	// answer is irrelevant.
	close(env.postRelease)

	if got := len(env.captured.all()); got != 0 {
		t.Fatalf("captured payloads after cancellation = %d, want none", got)
	}

	// The deferred release ran with a detached context: the permit is back
	// to reserved even though the request context was canceled.
	reservation = env.requireReservation(t, "run-dispatch-cancel")
	if reservation.Status != validatorcore.DispatchStatusReserved {
		t.Fatalf("status after cancellation = %q, want %q", reservation.Status, validatorcore.DispatchStatusReserved)
	}

	// The retry re-adopts the reservation, reuses the same provider
	// identity, and completes with exactly one remote share.
	w = env.doCreate(t, env.designatedBody())
	if w.Code != http.StatusCreated {
		t.Fatalf("retry status = %d, want 201: %s", w.Code, w.Body.String())
	}

	payloads := env.captured.all()
	if len(payloads) != 1 {
		t.Fatalf("captured payloads = %d, want 1", len(payloads))
	}

	if payloads[0].ProviderID != reservation.ProviderID {
		t.Fatalf("wire provider id = %q, want reserved %q", payloads[0].ProviderID, reservation.ProviderID)
	}

	env.requireState(t, "run-dispatch-cancel", validatorcore.StateForwardShareSent)

	reservation = env.requireReservation(t, "run-dispatch-cancel")
	if reservation.Status != validatorcore.DispatchStatusCASCommitted {
		t.Fatalf("reservation status = %q, want %q", reservation.Status, validatorcore.DispatchStatusCASCommitted)
	}

	shares := env.listShares(t)
	if len(shares) != 1 {
		t.Fatalf("stored shares = %d, want 1", len(shares))
	}

	if shares[0].ProviderID != reservation.ProviderID {
		t.Fatalf("share provider id = %q, want reserved %q", shares[0].ProviderID, reservation.ProviderID)
	}
}

// A client context canceled after delivery must not abort the commit: the
// CAS runs on a detached context and completes the outbox even though the
// request context is already canceled.
func TestDispatch_CanceledAfterDeliveryStillCommits(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t, true)
	env.seedActiveRun(t, "run-dispatch-late-cancel", validatorcore.StateReverseInviteAccepted)

	ctx, cancel := context.WithCancel(t.Context())
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/api/shares/outgoing", bytes.NewBufferString(env.designatedBody()))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	done := make(chan struct{})

	go func() {
		defer close(done)

		env.handler.HandleCreate(w, req)
	}()

	// The receiver accepted the share; the commit runs after delivery.
	select {
	case <-env.captured.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("receiver never saw the outbound POST")
	}

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("handler did not return after delivery")
	}

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", w.Code, w.Body.String())
	}

	// The client context is canceled only after delivery completed, so the
	// commit CAS and the local sent stamp ran under the detached context.
	cancel()

	env.requireState(t, "run-dispatch-late-cancel", validatorcore.StateForwardShareSent)

	reservation := env.requireReservation(t, "run-dispatch-late-cancel")
	if reservation.Status != validatorcore.DispatchStatusCASCommitted {
		t.Fatalf("reservation status = %q, want %q", reservation.Status, validatorcore.DispatchStatusCASCommitted)
	}

	shares := env.listShares(t)
	if len(shares) != 1 {
		t.Fatalf("stored shares = %d, want 1", len(shares))
	}

	if shares[0].Status != "sent" {
		t.Fatalf("share status = %q, want sent", shares[0].Status)
	}

	if got := len(env.captured.all()); got != 1 {
		t.Fatalf("captured payloads = %d, want 1", got)
	}
}

// A client context canceled while the commit CAS is in flight must not abort
// it: CommitSent runs on a detached bounded context, so the outbox completes
// even though the request is already gone. The local sent stamp still uses
// the request context and fails, which the idempotent replay then reconciles
// without a second outbound POST.
func TestDispatch_CanceledDuringCommitStillCompletes(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t, true)
	env.seedActiveRun(t, "run-dispatch-commit-cancel", validatorcore.StateReverseInviteAccepted)

	gate := &commitGateHook{
		DispatchHook: env.svc,
		entered:      make(chan struct{}),
		proceed:      make(chan struct{}),
	}
	env.handler.SetDispatchHook(gate)

	ctx, cancel := context.WithCancel(t.Context())
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/api/shares/outgoing", bytes.NewBufferString(env.designatedBody()))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	done := make(chan struct{})

	go func() {
		defer close(done)

		env.handler.HandleCreate(w, req)
	}()

	// The receiver accepted the share and the commit CAS is in flight.
	select {
	case <-gate.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("handler never reached the commit")
	}

	if got := env.postCount.Load(); got != 1 {
		t.Fatalf("receiver POSTs = %d, want 1", got)
	}

	// The client goes away mid-commit; the detached commit context must
	// outlive the cancellation.
	cancel()
	close(gate.proceed)

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("handler did not return after the commit was released")
	}

	// The commit CAS completed: the run advanced and the outbox row is
	// complete even though the request context was canceled during the
	// commit.
	env.requireState(t, "run-dispatch-commit-cancel", validatorcore.StateForwardShareSent)

	reservation := env.requireReservation(t, "run-dispatch-commit-cancel")
	if reservation.Status != validatorcore.DispatchStatusCASCommitted {
		t.Fatalf("reservation status = %q, want %q", reservation.Status, validatorcore.DispatchStatusCASCommitted)
	}

	// The local sent stamp ran on the canceled request context and failed,
	// so the first response reports the persistence failure.
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("first status = %d, want 500: %s", w.Code, w.Body.String())
	}

	// The replay reconciles the local row's sent status without a second
	// outbound POST.
	w = env.doCreate(t, env.designatedBody())
	if w.Code != http.StatusCreated {
		t.Fatalf("replay status = %d, want 201: %s", w.Code, w.Body.String())
	}

	if got := env.postCount.Load(); got != 1 {
		t.Fatalf("receiver POSTs after replay = %d, want exactly 1", got)
	}

	shares := env.listShares(t)
	if len(shares) != 1 {
		t.Fatalf("stored shares = %d, want 1", len(shares))
	}

	if shares[0].Status != "sent" {
		t.Fatalf("share status = %q, want sent", shares[0].Status)
	}
}

// A reservation left claimed by a dead dispatcher is reclaimed once stale,
// while a fresh claim still reports in progress.
func TestGuard_ReclaimsStaleClaimedReservation(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t, true)
	env.seedActiveRun(t, "run-guard-reclaim", validatorcore.StateReverseInviteAccepted)

	plan, err := env.svc.GuardCreate(t.Context(), designatedRequest(env), "run-guard-reclaim")
	if err != nil {
		t.Fatalf("guard: %v", err)
	}

	if plan == nil || plan.ReplayShare != nil {
		t.Fatalf("plan = %+v, want a fresh dispatch plan", plan)
	}

	// A live claim refuses the concurrent dispatcher.
	_, err = env.svc.GuardCreate(t.Context(), designatedRequest(env), "run-guard-reclaim")
	if err == nil {
		t.Fatal("expected in-progress refusal for a fresh claim")
	}

	// Once the claim goes stale, the next dispatcher reclaims it with the
	// same provider identity instead of being stranded on a refusal.
	env.ageReservation(t, "run-guard-reclaim", 3600)

	reclaimed, err := env.svc.GuardCreate(t.Context(), designatedRequest(env), "run-guard-reclaim")
	if err != nil {
		t.Fatalf("reclaim guard: %v", err)
	}

	if reclaimed == nil || reclaimed.ReplayShare != nil {
		t.Fatalf("reclaimed plan = %+v, want a fresh dispatch plan", reclaimed)
	}

	if reclaimed.ProviderID != plan.ProviderID {
		t.Fatalf("reclaimed provider id = %q, want %q", reclaimed.ProviderID, plan.ProviderID)
	}

	if reclaimed.SharedSecret != plan.SharedSecret {
		t.Fatal("reclaimed plan does not reuse the reserved shared secret")
	}

	if reclaimed.ClaimToken == "" || reclaimed.ClaimToken == plan.ClaimToken {
		t.Fatal("reclaim must rotate the claim token")
	}
}

// A stale claim reclaimed by a later dispatcher fences the old owner out: its
// late stamp is rejected, its plan is refused before the receiver sees a
// second POST, and its deferred release cannot free the new owner's permit,
// while the new owner completes the send with the same provider identity.
func TestDispatch_FencedStaleOwnerCannotRecordSecondSend(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t, true)
	env.seedActiveRun(t, "run-dispatch-fence", validatorcore.StateReverseInviteAccepted)

	plan, err := env.svc.GuardCreate(t.Context(), designatedRequest(env), "run-dispatch-fence")
	if err != nil {
		t.Fatalf("guard: %v", err)
	}

	// The old owner strands mid-send; a later dispatcher reclaims the stale
	// permit under a rotated claim token.
	env.ageReservation(t, "run-dispatch-fence", 3600)

	reclaimed, err := env.svc.GuardCreate(t.Context(), designatedRequest(env), "run-dispatch-fence")
	if err != nil {
		t.Fatalf("reclaim guard: %v", err)
	}

	// The fenced old owner's late stamp is rejected: its token no longer owns
	// the permit.
	err = env.store.MarkForwardDispatchRemoteSent(t.Context(), "run-dispatch-fence", plan.ProviderID, plan.ClaimToken, "share-old")
	if !errors.Is(err, validatorcore.ErrDispatchClaimLost) {
		t.Fatalf("stale owner stamp = %v, want ErrDispatchClaimLost", err)
	}

	// The fenced old plan is refused before the receiver sees a duplicate
	// POST: the token-gated URI snapshot rejects it with an internal failure
	// when the plan has no pinned wire URI yet, and the pre-send ownership
	// check rejects it with a conflict otherwise. Its deferred release
	// leaves the new owner's claim untouched either way.
	w := env.deliverPlan(t, plan)
	if w.Code != http.StatusConflict && w.Code != http.StatusInternalServerError {
		t.Fatalf("stale owner send status = %d, want 409 or 500: %s", w.Code, w.Body.String())
	}

	if got := env.postCount.Load(); got != 0 {
		t.Fatalf("receiver POSTs after fenced attempt = %d, want 0", got)
	}

	reservation := env.requireReservation(t, "run-dispatch-fence")
	if reservation.Status != validatorcore.DispatchStatusClaimed {
		t.Fatalf("status after fenced attempt = %q, want %q", reservation.Status, validatorcore.DispatchStatusClaimed)
	}

	// With the wire URI pinned on the plan, the snapshot seat is skipped and
	// the fenced attempt reaches the pre-send ownership check, which refuses
	// it with a conflict before any receiver POST.
	plan.WebDAVURI = reservation.WebDAVID

	w = env.deliverPlan(t, plan)
	if w.Code != http.StatusConflict {
		t.Fatalf("stale owner pinned send status = %d, want 409: %s", w.Code, w.Body.String())
	}

	if got := env.postCount.Load(); got != 0 {
		t.Fatalf("receiver POSTs after pinned fenced attempt = %d, want 0", got)
	}

	// The fenced old owner's late release is rejected too: it cannot free
	// the permit the new owner holds.
	err = env.store.ReleaseForwardDispatchClaim(t.Context(), "run-dispatch-fence", plan.ProviderID, plan.ClaimToken)
	if !errors.Is(err, validatorcore.ErrDispatchClaimLost) {
		t.Fatalf("stale owner release = %v, want ErrDispatchClaimLost", err)
	}

	// The new owner sends and completes with the same provider identity.
	// The reclaimed plan from the second guard call already holds the send
	// permit, so the handler drives it directly.
	requirePlanDelivers(t, env, "run-dispatch-fence", reclaimed)
}

// requirePlanDelivers drives the delivery path with a permit-holding plan
// and asserts exactly one receiver POST carrying the reserved provider
// identity, the run advancing, and the commit CAS landing.
func requirePlanDelivers(t *testing.T, env *testEnv, runID string, plan *outgoingshares.DispatchPlan) {
	t.Helper()

	w := env.deliverPlan(t, plan)
	if w.Code != http.StatusCreated {
		t.Fatalf("deliver status = %d, want 201: %s", w.Code, w.Body.String())
	}

	if got := env.postCount.Load(); got != 1 {
		t.Fatalf("receiver POSTs = %d, want exactly 1", got)
	}

	payloads := env.captured.all()
	if len(payloads) != 1 {
		t.Fatalf("captured payloads = %d, want 1", len(payloads))
	}

	if payloads[0].ProviderID != plan.ProviderID {
		t.Fatalf("wire provider id = %q, want reserved %q", payloads[0].ProviderID, plan.ProviderID)
	}

	env.requireState(t, runID, validatorcore.StateForwardShareSent)

	reservation := env.requireReservation(t, runID)
	if reservation.Status != validatorcore.DispatchStatusCASCommitted {
		t.Fatalf("reservation status = %q, want %q", reservation.Status, validatorcore.DispatchStatusCASCommitted)
	}
}
