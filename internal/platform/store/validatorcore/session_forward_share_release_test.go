// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"errors"
	"testing"
	"time"
)

// The commit CAS binds the exact snapshotted wire URI: after the reservation
// records the absolute URI the dispatch sent, a commit naming anything else
// is refused, and only the exact snapshot commits.
func TestCommitForwardShareSent_WireURIConjunct(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-fwd-commit-uri"

	seedForwardRun(t, core, runID, StateReverseInviteAccepted)

	if err := core.ReserveForwardDispatch(ctx, forwardReservationInput(runID, "prov-1")); err != nil {
		t.Fatalf("reserve: %v", err)
	}

	if err := core.ClaimForwardDispatchSend(ctx, runID, "prov-1", "tok-1"); err != nil {
		t.Fatalf("claim: %v", err)
	}

	const wireURI = "https://peer.example/webdav/webdav-prov-1"

	if err := core.SnapshotForwardDispatchWireURI(ctx, runID, "prov-1", "tok-1", wireURI); err != nil {
		t.Fatalf("snapshot wire uri: %v", err)
	}

	if err := core.MarkForwardDispatchRemoteSent(ctx, runID, "prov-1", "tok-1", "share-1"); err != nil {
		t.Fatalf("mark remote sent: %v", err)
	}

	// The pre-snapshot bare ID no longer matches the stored wire identity.
	stale := forwardCommitInput(runID)
	stale.WebDAVURI = "webdav-prov-1"

	if err := core.CommitForwardShareSent(ctx, stale); !errors.Is(err, ErrDispatchConjunctMismatch) {
		t.Fatalf("commit with stale bare id = %v, want ErrDispatchConjunctMismatch", err)
	}

	commit := forwardCommitInput(runID)
	commit.WebDAVURI = wireURI

	if err := core.CommitForwardShareSent(ctx, commit); err != nil {
		t.Fatalf("commit with exact wire uri: %v", err)
	}

	requireState(t, core, runID, StateForwardShareSent)

	if got := getReservation(t, core, runID).Status; got != DispatchStatusCASCommitted {
		t.Fatalf("status = %q, want %q", got, DispatchStatusCASCommitted)
	}
}

func TestReclaimForwardDispatchClaim_RetakesOnlyStaleClaims(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-fwd-reclaim"

	seedForwardRun(t, core, runID, StateReverseInviteAccepted)

	if err := core.ReserveForwardDispatch(ctx, forwardReservationInput(runID, "prov-1")); err != nil {
		t.Fatalf("reserve: %v", err)
	}

	now := time.Now().Unix()

	// A reserved row has no claimed permit to reclaim.
	if err := core.ReclaimForwardDispatchClaim(ctx, runID, "prov-1", "tok-1", "tok-2", now+1); !errors.Is(err, ErrDispatchClaimMiss) {
		t.Fatalf("reclaim reserved = %v, want ErrDispatchClaimMiss", err)
	}

	if err := core.ClaimForwardDispatchSend(ctx, runID, "prov-1", "tok-1"); err != nil {
		t.Fatalf("claim: %v", err)
	}

	// A fresh claim is still owned by the live dispatcher: with the real
	// staleness bound the row is too young to reclaim.
	if err := core.ReclaimForwardDispatchClaim(ctx, runID, "prov-1", "tok-1", "tok-2", now-30); !errors.Is(err, ErrDispatchClaimMiss) {
		t.Fatalf("reclaim fresh claim = %v, want ErrDispatchClaimMiss", err)
	}

	// Backdate the claim past the staleness bound, the stranded-owner case.
	if err := core.DB().WithContext(ctx).Table(tableDispatchReservation).
		Where("test_run_id = ?", runID).
		Update("updated_at", now-3600).Error; err != nil {
		t.Fatalf("backdate claim: %v", err)
	}

	// A stale claim still refuses a reclaim that names the wrong observed
	// token: the permit changed hands since the caller's observation.
	if err := core.ReclaimForwardDispatchClaim(ctx, runID, "prov-1", "tok-stale", "tok-2", now-30); !errors.Is(err, ErrDispatchClaimMiss) {
		t.Fatalf("reclaim with wrong observed token = %v, want ErrDispatchClaimMiss", err)
	}

	if err := core.ReclaimForwardDispatchClaim(ctx, runID, "prov-1", "tok-1", "tok-2", now-30); err != nil {
		t.Fatalf("reclaim stale claim: %v", err)
	}

	reservation := getReservation(t, core, runID)
	if reservation.Status != DispatchStatusClaimed {
		t.Fatalf("status = %q, want %q", reservation.Status, DispatchStatusClaimed)
	}

	if reservation.UpdatedAt == nil || *reservation.UpdatedAt < now {
		t.Fatalf("updated_at = %v, want freshened to now", reservation.UpdatedAt)
	}

	// A different provider identity never reclaims the permit.
	if err := core.ReclaimForwardDispatchClaim(ctx, runID, "prov-2", "tok-2", "tok-3", now+1); !errors.Is(err, ErrDispatchClaimMiss) {
		t.Fatalf("reclaim wrong provider = %v, want ErrDispatchClaimMiss", err)
	}

	// A recorded send is never reclaimed.
	if err := core.MarkForwardDispatchRemoteSent(ctx, runID, "prov-1", "tok-2", "share-1"); err != nil {
		t.Fatalf("mark remote sent: %v", err)
	}

	if err := core.ReclaimForwardDispatchClaim(ctx, runID, "prov-1", "tok-2", "tok-3", now+1); !errors.Is(err, ErrDispatchClaimMiss) {
		t.Fatalf("reclaim remote sent = %v, want ErrDispatchClaimMiss", err)
	}
}

// A reclaimed stale claim rotates the claim token, so the fenced old owner
// can no longer stamp, snapshot, or release the permit, while the new owner
// completes the send normally.
func TestReclaimForwardDispatchClaim_FencesStaleOwner(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-fwd-fence"

	seedForwardRun(t, core, runID, StateReverseInviteAccepted)

	if err := core.ReserveForwardDispatch(ctx, forwardReservationInput(runID, "prov-1")); err != nil {
		t.Fatalf("reserve: %v", err)
	}

	if err := core.ClaimForwardDispatchSend(ctx, runID, "prov-1", "tok-1"); err != nil {
		t.Fatalf("claim: %v", err)
	}

	// The old owner strands: the claim goes stale and a later dispatcher
	// reclaims it under a new token.
	if err := core.DB().WithContext(ctx).Table(tableDispatchReservation).
		Where("test_run_id = ?", runID).
		Update("updated_at", time.Now().Unix()-3600).Error; err != nil {
		t.Fatalf("backdate claim: %v", err)
	}

	if err := core.ReclaimForwardDispatchClaim(ctx, runID, "prov-1", "tok-1", "tok-2", time.Now().Unix()-30); err != nil {
		t.Fatalf("reclaim stale claim: %v", err)
	}

	// Every owner-side write from the fenced old owner fails closed.
	if err := core.SnapshotForwardDispatchWireURI(ctx, runID, "prov-1", "tok-1", "https://peer.example/webdav/webdav-prov-1"); !errors.Is(err, ErrDispatchClaimLost) {
		t.Fatalf("stale owner snapshot = %v, want ErrDispatchClaimLost", err)
	}

	if err := core.MarkForwardDispatchRemoteSent(ctx, runID, "prov-1", "tok-1", "share-1"); !errors.Is(err, ErrDispatchClaimLost) {
		t.Fatalf("stale owner stamp = %v, want ErrDispatchClaimLost", err)
	}

	if err := core.ReleaseForwardDispatchClaim(ctx, runID, "prov-1", "tok-1"); !errors.Is(err, ErrDispatchClaimLost) {
		t.Fatalf("stale owner release = %v, want ErrDispatchClaimLost", err)
	}

	// The new owner completes the send under its token.
	if err := core.MarkForwardDispatchRemoteSent(ctx, runID, "prov-1", "tok-2", "share-1"); err != nil {
		t.Fatalf("new owner stamp: %v", err)
	}

	reservation := getReservation(t, core, runID)
	if reservation.Status != DispatchStatusRemoteSent {
		t.Fatalf("status = %q, want %q", reservation.Status, DispatchStatusRemoteSent)
	}

	if reservation.OutgoingShareID == nil || *reservation.OutgoingShareID != "share-1" {
		t.Fatalf("outgoing share id = %v, want share-1", reservation.OutgoingShareID)
	}
}

func TestReleaseForwardDispatchClaim_ReturnsPermitToReserved(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-fwd-release"

	seedForwardRun(t, core, runID, StateReverseInviteAccepted)

	if err := core.ReserveForwardDispatch(ctx, forwardReservationInput(runID, "prov-1")); err != nil {
		t.Fatalf("reserve: %v", err)
	}

	if err := core.ClaimForwardDispatchSend(ctx, runID, "prov-1", "tok-1"); err != nil {
		t.Fatalf("claim: %v", err)
	}

	if err := core.ReleaseForwardDispatchClaim(ctx, runID, "prov-1", "tok-1"); err != nil {
		t.Fatalf("release: %v", err)
	}

	if got := getReservation(t, core, runID).Status; got != DispatchStatusReserved {
		t.Fatalf("status = %q, want %q", got, DispatchStatusReserved)
	}

	// The released permit can be taken again by the same provider identity.
	if err := core.ClaimForwardDispatchSend(ctx, runID, "prov-1", "tok-2"); err != nil {
		t.Fatalf("re-claim after release: %v", err)
	}

	// A repeat release is idempotent once the row is no longer claimed.
	if err := core.ReleaseForwardDispatchClaim(ctx, runID, "prov-1", "tok-2"); err != nil {
		t.Fatalf("release of re-claimed row: %v", err)
	}

	if got := getReservation(t, core, runID).Status; got != DispatchStatusReserved {
		t.Fatalf("status after repeat release = %q, want %q", got, DispatchStatusReserved)
	}
}

func TestReleaseForwardDispatchClaim_NeverReleasesRecordedSend(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-fwd-release-sent"

	seedForwardRun(t, core, runID, StateReverseInviteAccepted)
	reserveClaimMark(t, core, runID)

	// A recorded remote send is not releasable; the replay path owns it.
	if err := core.ReleaseForwardDispatchClaim(ctx, runID, "prov-1", "tok-1"); err != nil {
		t.Fatalf("release after remote sent: %v", err)
	}

	if got := getReservation(t, core, runID).Status; got != DispatchStatusRemoteSent {
		t.Fatalf("status = %q, want %q", got, DispatchStatusRemoteSent)
	}

	if err := core.CommitForwardShareSent(ctx, forwardCommitInput(runID)); err != nil {
		t.Fatalf("commit: %v", err)
	}

	if err := core.ReleaseForwardDispatchClaim(ctx, runID, "prov-1", "tok-1"); err != nil {
		t.Fatalf("release after commit: %v", err)
	}

	if got := getReservation(t, core, runID).Status; got != DispatchStatusCASCommitted {
		t.Fatalf("status = %q, want %q", got, DispatchStatusCASCommitted)
	}

	// A release naming a different provider identity never matches.
	err := core.ReleaseForwardDispatchClaim(ctx, runID, "prov-2", "tok-2")
	if !errors.Is(err, ErrDispatchConjunctMismatch) {
		t.Fatalf("release wrong provider = %v, want ErrDispatchConjunctMismatch", err)
	}
}

func TestSnapshotForwardDispatchWireURI_PinsExactWireForm(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-fwd-wire-uri"

	seedForwardRun(t, core, runID, StateReverseInviteAccepted)

	if err := core.ReserveForwardDispatch(ctx, forwardReservationInput(runID, "prov-1")); err != nil {
		t.Fatalf("reserve: %v", err)
	}

	// The reservation starts with the bare minted ID.
	if got := getReservation(t, core, runID).WebDAVID; got != "webdav-prov-1" {
		t.Fatalf("webdav id = %q, want webdav-prov-1", got)
	}

	const wireURI = "https://peer.example/webdav/webdav-prov-1"

	// The snapshot is an owner-side write: without the send permit it never
	// writes, even on a freshly reserved row.
	if err := core.SnapshotForwardDispatchWireURI(ctx, runID, "prov-1", "tok-none", wireURI); err == nil {
		t.Fatal("snapshot without the send permit must fail")
	}

	if got := getReservation(t, core, runID).WebDAVID; got != "webdav-prov-1" {
		t.Fatalf("webdav id after unowned snapshot = %q, want webdav-prov-1", got)
	}

	if err := core.ClaimForwardDispatchSend(ctx, runID, "prov-1", "tok-1"); err != nil {
		t.Fatalf("claim: %v", err)
	}

	if err := core.SnapshotForwardDispatchWireURI(ctx, runID, "prov-1", "tok-1", wireURI); err != nil {
		t.Fatalf("snapshot: %v", err)
	}

	if got := getReservation(t, core, runID).WebDAVID; got != wireURI {
		t.Fatalf("webdav id = %q, want %q", got, wireURI)
	}

	// The snapshot stays writable inside the send window and is idempotent.
	if err := core.SnapshotForwardDispatchWireURI(ctx, runID, "prov-1", "tok-1", wireURI); err != nil {
		t.Fatalf("repeat snapshot: %v", err)
	}
}

func TestSnapshotForwardDispatchWireURI_RefusesOutsideSendWindow(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-fwd-wire-uri-late"

	seedForwardRun(t, core, runID, StateReverseInviteAccepted)
	reserveClaimMark(t, core, runID)

	// After the remote send is recorded the wire identity is frozen.
	err := core.SnapshotForwardDispatchWireURI(ctx, runID, "prov-1", "tok-1", "https://peer.example/drifted/webdav-prov-1")
	if !errors.Is(err, ErrDispatchConjunctMismatch) {
		t.Fatalf("snapshot after remote sent = %v, want ErrDispatchConjunctMismatch", err)
	}

	if got := getReservation(t, core, runID).WebDAVID; got != "webdav-prov-1" {
		t.Fatalf("webdav id = %q, want webdav-prov-1", got)
	}

	// A snapshot naming a different provider identity never matches.
	err = core.SnapshotForwardDispatchWireURI(ctx, runID, "prov-2", "tok-2", "webdav-prov-1")
	if !errors.Is(err, ErrDispatchConjunctMismatch) {
		t.Fatalf("snapshot wrong provider = %v, want ErrDispatchConjunctMismatch", err)
	}
}

// A stale owner whose claim token was rotated by a reclaim can never
// overwrite the winner's wire identity: its snapshot fails closed and the
// stored URI stays untouched, while the new owner snapshots freely.
func TestSnapshotForwardDispatchWireURI_TokenGated(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-fwd-wire-fence"

	seedForwardRun(t, core, runID, StateReverseInviteAccepted)

	if err := core.ReserveForwardDispatch(ctx, forwardReservationInput(runID, "prov-1")); err != nil {
		t.Fatalf("reserve: %v", err)
	}

	if err := core.ClaimForwardDispatchSend(ctx, runID, "prov-1", "tok-a"); err != nil {
		t.Fatalf("claim: %v", err)
	}

	const winnerURI = "https://peer.example/webdav/webdav-prov-1"

	if err := core.SnapshotForwardDispatchWireURI(ctx, runID, "prov-1", "tok-a", winnerURI); err != nil {
		t.Fatalf("owner snapshot: %v", err)
	}

	// The owner strands: the claim goes stale and a later dispatcher
	// reclaims it under a rotated token.
	if err := core.DB().WithContext(ctx).Table(tableDispatchReservation).
		Where("test_run_id = ?", runID).
		Update("updated_at", time.Now().Unix()-3600).Error; err != nil {
		t.Fatalf("backdate claim: %v", err)
	}

	if err := core.ReclaimForwardDispatchClaim(ctx, runID, "prov-1", "tok-a", "tok-b", time.Now().Unix()-30); err != nil {
		t.Fatalf("reclaim stale claim: %v", err)
	}

	// The fenced owner fails closed, whether it writes a drifted URI or
	// repeats the exact stored value.
	err := core.SnapshotForwardDispatchWireURI(ctx, runID, "prov-1", "tok-a", "https://peer.example/drifted/webdav-prov-1")
	if !errors.Is(err, ErrDispatchClaimLost) {
		t.Fatalf("fenced snapshot with drifted uri = %v, want ErrDispatchClaimLost", err)
	}

	if err := core.SnapshotForwardDispatchWireURI(ctx, runID, "prov-1", "tok-a", winnerURI); !errors.Is(err, ErrDispatchClaimLost) {
		t.Fatalf("fenced snapshot with stored uri = %v, want ErrDispatchClaimLost", err)
	}

	if got := getReservation(t, core, runID).WebDAVID; got != winnerURI {
		t.Fatalf("webdav id after fenced snapshots = %q, want %q", got, winnerURI)
	}

	// The new owner snapshots and updates the wire identity under its token.
	const retryURI = "https://peer.example/webdav2/webdav-prov-1"

	if err := core.SnapshotForwardDispatchWireURI(ctx, runID, "prov-1", "tok-b", retryURI); err != nil {
		t.Fatalf("new owner snapshot: %v", err)
	}

	if got := getReservation(t, core, runID).WebDAVID; got != retryURI {
		t.Fatalf("webdav id after new owner snapshot = %q, want %q", got, retryURI)
	}
}

// The pre-send ownership check passes only for the current permit owner: a
// fenced token, a released permit, and a recorded send all fail closed.
func TestCheckForwardDispatchClaim_OwnershipWindow(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-fwd-claim-check"

	seedForwardRun(t, core, runID, StateReverseInviteAccepted)

	if err := core.ReserveForwardDispatch(ctx, forwardReservationInput(runID, "prov-1")); err != nil {
		t.Fatalf("reserve: %v", err)
	}

	// Reserved but unclaimed: nobody owns the send permit yet.
	if err := core.CheckForwardDispatchClaim(ctx, runID, "prov-1", "tok-1"); !errors.Is(err, ErrDispatchClaimLost) {
		t.Fatalf("check reserved = %v, want ErrDispatchClaimLost", err)
	}

	if err := core.ClaimForwardDispatchSend(ctx, runID, "prov-1", "tok-1"); err != nil {
		t.Fatalf("claim: %v", err)
	}

	if err := core.CheckForwardDispatchClaim(ctx, runID, "prov-1", "tok-1"); err != nil {
		t.Fatalf("check current owner: %v", err)
	}

	// A token that never owned the permit fails closed.
	if err := core.CheckForwardDispatchClaim(ctx, runID, "prov-1", "tok-other"); !errors.Is(err, ErrDispatchClaimLost) {
		t.Fatalf("check wrong token = %v, want ErrDispatchClaimLost", err)
	}

	// A different provider identity never matches.
	if err := core.CheckForwardDispatchClaim(ctx, runID, "prov-2", "tok-1"); !errors.Is(err, ErrDispatchConjunctMismatch) {
		t.Fatalf("check wrong provider = %v, want ErrDispatchConjunctMismatch", err)
	}

	// After a fenced reclaim only the rotated token owns the permit.
	if err := core.DB().WithContext(ctx).Table(tableDispatchReservation).
		Where("test_run_id = ?", runID).
		Update("updated_at", time.Now().Unix()-3600).Error; err != nil {
		t.Fatalf("backdate claim: %v", err)
	}

	if err := core.ReclaimForwardDispatchClaim(ctx, runID, "prov-1", "tok-1", "tok-2", time.Now().Unix()-30); err != nil {
		t.Fatalf("reclaim stale claim: %v", err)
	}

	if err := core.CheckForwardDispatchClaim(ctx, runID, "prov-1", "tok-1"); !errors.Is(err, ErrDispatchClaimLost) {
		t.Fatalf("check fenced token = %v, want ErrDispatchClaimLost", err)
	}

	if err := core.CheckForwardDispatchClaim(ctx, runID, "prov-1", "tok-2"); err != nil {
		t.Fatalf("check new owner: %v", err)
	}

	// Once the send is recorded the pre-send window is closed for everyone.
	if err := core.MarkForwardDispatchRemoteSent(ctx, runID, "prov-1", "tok-2", "share-1"); err != nil {
		t.Fatalf("mark remote sent: %v", err)
	}

	if err := core.CheckForwardDispatchClaim(ctx, runID, "prov-1", "tok-2"); !errors.Is(err, ErrDispatchClaimLost) {
		t.Fatalf("check after remote sent = %v, want ErrDispatchClaimLost", err)
	}
}
