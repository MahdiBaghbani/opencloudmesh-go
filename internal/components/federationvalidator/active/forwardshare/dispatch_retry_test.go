// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package forwardshare_test

import (
	"net/http"
	"strings"
	"testing"

	ocmshares "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

// A failed send releases the send permit: the reservation returns to
// reserved, and a later attempt retries with the same provider identity and
// the snapshotted payload instead of stranding the run.
func TestDispatch_FailedSendReleasesPermitForRetry(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t, true)
	env.seedActiveRun(t, "run-dispatch-retry", validatorcore.StateReverseInviteAccepted)

	// First attempt: the receiver never creates a row.
	env.failPosts.Store(1)

	w := env.doCreate(t, env.designatedBody())
	if w.Code != http.StatusBadGateway {
		t.Fatalf("failed send status = %d, want 502: %s", w.Code, w.Body.String())
	}

	reservation := env.requireReservation(t, "run-dispatch-retry")
	if reservation.Status != validatorcore.DispatchStatusReserved {
		t.Fatalf("reservation status after failed send = %q, want %q", reservation.Status, validatorcore.DispatchStatusReserved)
	}

	shares := env.listShares(t)
	if len(shares) != 1 {
		t.Fatalf("stored shares = %d, want 1", len(shares))
	}

	if shares[0].Status != ocmshares.OutgoingShareStatusFailed {
		t.Fatalf("share status after failed send = %q, want %q", shares[0].Status, ocmshares.OutgoingShareStatusFailed)
	}

	// Retry with a healthy receiver: the same provider identity goes out
	// again and the dispatch completes.
	w = env.doCreate(t, env.designatedBody())
	if w.Code != http.StatusCreated {
		t.Fatalf("retry status = %d, want 201: %s", w.Code, w.Body.String())
	}

	if got := env.postCount.Load(); got != 2 {
		t.Fatalf("outbound POSTs = %d, want 2", got)
	}

	payloads := env.captured.all()
	if len(payloads) != 1 {
		t.Fatalf("captured payloads = %d, want 1", len(payloads))
	}

	if payloads[0].ProviderID != reservation.ProviderID {
		t.Fatalf("wire provider id = %q, want reserved %q", payloads[0].ProviderID, reservation.ProviderID)
	}

	env.requireState(t, "run-dispatch-retry", validatorcore.StateForwardShareSent)

	reservation = env.requireReservation(t, "run-dispatch-retry")
	if reservation.Status != validatorcore.DispatchStatusCASCommitted {
		t.Fatalf("reservation status = %q, want %q", reservation.Status, validatorcore.DispatchStatusCASCommitted)
	}

	shares = env.listShares(t)
	if len(shares) != 1 {
		t.Fatalf("stored shares = %d, want 1", len(shares))
	}

	if shares[0].Status != ocmshares.OutgoingShareStatusSent || shares[0].Error != "" {
		t.Fatalf("share after retry = (%q, %q), want (%q, empty error)", shares[0].Status, shares[0].Error, ocmshares.OutgoingShareStatusSent)
	}
}

// An uncertain send (the receiver stored the row but reported a failure)
// retries with the identical payload, which the receiver deduplicates by
// provider ID: exactly one remote share exists after the retry.
func TestDispatch_UncertainSendReplaysIdenticalPayload(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t, true)
	env.seedActiveRun(t, "run-dispatch-uncertain", validatorcore.StateReverseInviteAccepted)

	env.flakyPosts.Store(1)

	w := env.doCreate(t, env.designatedBody())
	if w.Code != http.StatusBadGateway {
		t.Fatalf("uncertain send status = %d, want 502: %s", w.Code, w.Body.String())
	}

	if got := len(env.captured.all()); got != 1 {
		t.Fatalf("captured payloads after uncertain send = %d, want 1", got)
	}

	w = env.doCreate(t, env.designatedBody())
	if w.Code != http.StatusCreated {
		t.Fatalf("retry status = %d, want 201: %s", w.Code, w.Body.String())
	}

	if got := env.postCount.Load(); got != 2 {
		t.Fatalf("outbound POSTs = %d, want 2", got)
	}

	// The identical replay was deduplicated: still exactly one remote row.
	payloads := env.captured.all()
	if len(payloads) != 1 {
		t.Fatalf("captured payloads = %d, want 1", len(payloads))
	}

	reservation := env.requireReservation(t, "run-dispatch-uncertain")
	if payloads[0].ProviderID != reservation.ProviderID {
		t.Fatalf("wire provider id = %q, want reserved %q", payloads[0].ProviderID, reservation.ProviderID)
	}

	env.requireState(t, "run-dispatch-uncertain", validatorcore.StateForwardShareSent)
}

// A retry after discovery drift replays the exact wire URI the first attempt
// snapshotted, never a URI rebuilt from the changed discovery document.
func TestDispatch_RetryKeepsExactWireURIUnderDiscoveryDrift(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t, true)
	env.seedActiveRun(t, "run-dispatch-drift", validatorcore.StateReverseInviteAccepted)

	// The receiver advertises an absolute webdav-receive URI, so the wire
	// URI carries the advertised path; then the first send fails cleanly.
	env.driftDiscovery("/webdav")
	env.failPosts.Store(1)

	w := env.doCreate(t, env.designatedBody())
	if w.Code != http.StatusBadGateway {
		t.Fatalf("failed send status = %d, want 502: %s", w.Code, w.Body.String())
	}

	reservation := env.requireReservation(t, "run-dispatch-drift")
	if !strings.Contains(reservation.WebDAVID, "/webdav/") {
		t.Fatalf("snapshotted wire uri = %q, want the absolute first-attempt form", reservation.WebDAVID)
	}

	// Discovery drifts before the retry; the retry must still send the
	// snapshotted URI.
	env.driftDiscovery("/drifted")

	w = env.doCreate(t, env.designatedBody())
	if w.Code != http.StatusCreated {
		t.Fatalf("retry status = %d, want 201: %s", w.Code, w.Body.String())
	}

	payloads := env.captured.all()
	if len(payloads) != 1 {
		t.Fatalf("captured payloads = %d, want 1", len(payloads))
	}

	wireURI := payloads[0].Protocol.WebDAV.URI
	if wireURI != reservation.WebDAVID {
		t.Fatalf("wire uri = %q, want snapshotted %q", wireURI, reservation.WebDAVID)
	}

	if strings.Contains(wireURI, "/drifted/") {
		t.Fatalf("wire uri = %q was rebuilt from drifted discovery", wireURI)
	}

	env.requireState(t, "run-dispatch-drift", validatorcore.StateForwardShareSent)
}

// A replay after a crash between the remote send and the local sent stamp
// reconciles the local row's delivery status without a second outbound POST.
func TestDispatch_ReplayReconcilesLocalSentStatus(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t, true)
	env.seedActiveRun(t, "run-dispatch-reconcile", validatorcore.StateReverseInviteAccepted)

	plan, err := env.svc.GuardCreate(t.Context(), designatedRequest(env), "run-dispatch-reconcile")
	if err != nil {
		t.Fatalf("guard: %v", err)
	}

	// The remote send succeeded but the local row never left pending.
	env.persistDispatchedShareWithStatus(t, plan, ocmshares.OutgoingShareStatusPending)

	if err := env.store.MarkForwardDispatchRemoteSent(t.Context(), "run-dispatch-reconcile", plan.ProviderID, plan.ClaimToken, ""); err != nil {
		t.Fatalf("mark remote sent: %v", err)
	}

	w := env.doCreate(t, env.designatedBody())
	if w.Code != http.StatusCreated {
		t.Fatalf("replay status = %d, want 201: %s", w.Code, w.Body.String())
	}

	if got := env.postCount.Load(); got != 0 {
		t.Fatalf("outbound POSTs = %d, want none on replay", got)
	}

	shares := env.listShares(t)
	if len(shares) != 1 {
		t.Fatalf("stored shares = %d, want 1", len(shares))
	}

	if shares[0].Status != ocmshares.OutgoingShareStatusSent {
		t.Fatalf("share status after replay = %q, want %q", shares[0].Status, ocmshares.OutgoingShareStatusSent)
	}

	if shares[0].SentAt == nil {
		t.Fatal("share sent stamp not reconciled")
	}

	env.requireState(t, "run-dispatch-reconcile", validatorcore.StateForwardShareSent)

	reservation := env.requireReservation(t, "run-dispatch-reconcile")
	if reservation.Status != validatorcore.DispatchStatusCASCommitted {
		t.Fatalf("reservation status = %q, want %q", reservation.Status, validatorcore.DispatchStatusCASCommitted)
	}
}
