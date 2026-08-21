// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const forwardDesignated = "alice"

// seedForwardRun seeds the singleton active run in the given state with the
// designated recipient pin the invite acceptance would have written.
func seedForwardRun(t *testing.T, core *Core, runID, state string) {
	t.Helper()

	now := time.Now().Unix()
	designated := forwardDesignated

	if err := core.DB().WithContext(t.Context()).Create(&TestRun{
		TestRunID:           runID,
		IsActive:            true,
		State:               state,
		SessionKind:         SessionKindActiveFull,
		TargetHost:          "peer.example",
		DesignatedShareWith: &designated,
		CreatedAt:           now,
		UpdatedAt:           now,
	}).Error; err != nil {
		t.Fatalf("seed forward run %s: %v", runID, err)
	}
}

func forwardReservationInput(runID, providerID string) ForwardDispatchReservation {
	return ForwardDispatchReservation{
		TestRunID:           runID,
		ProviderID:          providerID,
		WebDAVID:            "webdav-" + providerID,
		SharedSecret:        "secret-" + providerID,
		ReceiverHost:        "peer.example",
		ShareWith:           forwardDesignated + "@peer.example",
		DesignatedShareWith: forwardDesignated,
		ProbeFilePath:       "/tmp/probe.txt",
	}
}

// reserveClaimMark drives a reservation to remote_sent the way the dispatch
// path does, using the provider identity forwardCommitInput commits with.
func reserveClaimMark(t *testing.T, core *Core, runID string) {
	t.Helper()

	ctx := t.Context()
	providerID := "prov-1"

	if err := core.ReserveForwardDispatch(ctx, forwardReservationInput(runID, providerID)); err != nil {
		t.Fatalf("reserve: %v", err)
	}

	if err := core.ClaimForwardDispatchSend(ctx, runID, providerID, "tok-1"); err != nil {
		t.Fatalf("claim: %v", err)
	}

	if err := core.MarkForwardDispatchRemoteSent(ctx, runID, providerID, "tok-1", "share-1"); err != nil {
		t.Fatalf("mark remote sent: %v", err)
	}
}

func forwardCommitInput(runID string) ForwardShareCommit {
	return ForwardShareCommit{
		TestRunID:           runID,
		ProviderID:          "prov-1",
		ReceiverHost:        "peer.example",
		ShareWith:           forwardDesignated + "@peer.example",
		DesignatedShareWith: forwardDesignated,
		ProbeFilePath:       "/tmp/probe.txt",
		WebDAVURI:           "webdav-prov-1",
		OutgoingShareID:     "share-1",
	}
}

func getReservation(t *testing.T, core *Core, runID string) *DispatchReservation {
	t.Helper()

	reservation, err := core.GetDispatchReservation(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetDispatchReservation: %v", err)
	}

	return reservation
}

func TestReserveForwardDispatch_ReservesAndRejectsSecondReserve(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-fwd-reserve"

	seedForwardRun(t, core, runID, StateReverseInviteAccepted)

	if err := core.ReserveForwardDispatch(ctx, forwardReservationInput(runID, "prov-1")); err != nil {
		t.Fatalf("reserve: %v", err)
	}

	reservation := getReservation(t, core, runID)
	if reservation.Status != DispatchStatusReserved {
		t.Fatalf("status = %q, want %q", reservation.Status, DispatchStatusReserved)
	}

	err := core.ReserveForwardDispatch(ctx, forwardReservationInput(runID, "prov-2"))
	if !errors.Is(err, ErrDispatchReservationExists) {
		t.Fatalf("second reserve = %v, want ErrDispatchReservationExists", err)
	}

	// The winner's identity is untouched.
	if got := getReservation(t, core, runID).ProviderID; got != "prov-1" {
		t.Fatalf("provider id = %q, want prov-1", got)
	}
}

func TestReserveForwardDispatch_ConcurrentReservesHaveOneWinner(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	runID := "run-fwd-reserve-race"

	seedForwardRun(t, core, runID, StateReverseInviteAccepted)

	const racers = 8

	var wg sync.WaitGroup

	wins := make(chan string, racers)

	for i := range racers {
		wg.Add(1)

		go func() {
			defer wg.Done()

			providerID := fmt.Sprintf("prov-%d", i)
			if err := core.ReserveForwardDispatch(t.Context(), forwardReservationInput(runID, providerID)); err == nil {
				wins <- providerID
			}
		}()
	}

	wg.Wait()
	close(wins)

	var winners []string
	for w := range wins {
		winners = append(winners, w)
	}

	if len(winners) != 1 {
		t.Fatalf("reserve winners = %v, want exactly one", winners)
	}

	if got := getReservation(t, core, runID).ProviderID; got != winners[0] {
		t.Fatalf("reservation provider id = %q, want winner %q", got, winners[0])
	}
}

func TestReserveForwardDispatch_RejectsWrongStateAndConjuncts(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		state  string
		mutate func(*ForwardDispatchReservation)
	}{
		{
			name:   "wrong state",
			state:  StateActiveRunning,
			mutate: func(*ForwardDispatchReservation) {},
		},
		{
			name:  "wrong designated pin",
			state: StateReverseInviteAccepted,
			mutate: func(in *ForwardDispatchReservation) {
				in.DesignatedShareWith = "mallory"
			},
		},
		{
			name:  "wrong receiver host",
			state: StateReverseInviteAccepted,
			mutate: func(in *ForwardDispatchReservation) {
				in.ReceiverHost = "other.example"
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			core := openTestCore(t)
			runID := "run-fwd-mismatch"

			seedForwardRun(t, core, runID, tc.state)

			in := forwardReservationInput(runID, "prov-1")
			tc.mutate(&in)

			err := core.ReserveForwardDispatch(t.Context(), in)
			if !errors.Is(err, ErrStateTransitionMiss) {
				t.Fatalf("reserve = %v, want ErrStateTransitionMiss", err)
			}

			requireState(t, core, runID, tc.state)
		})
	}
}

func TestClaimForwardDispatchSend_SingleWinner(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-fwd-claim"

	seedForwardRun(t, core, runID, StateReverseInviteAccepted)

	if err := core.ReserveForwardDispatch(ctx, forwardReservationInput(runID, "prov-1")); err != nil {
		t.Fatalf("reserve: %v", err)
	}

	if err := core.ClaimForwardDispatchSend(ctx, runID, "prov-1", "tok-1"); err != nil {
		t.Fatalf("claim: %v", err)
	}

	if got := getReservation(t, core, runID).Status; got != DispatchStatusClaimed {
		t.Fatalf("status = %q, want %q", got, DispatchStatusClaimed)
	}

	// The permit is gone: a second claim fails even with the right identity.
	if err := core.ClaimForwardDispatchSend(ctx, runID, "prov-1", "tok-2"); !errors.Is(err, ErrDispatchClaimMiss) {
		t.Fatalf("second claim = %v, want ErrDispatchClaimMiss", err)
	}

	// A claim against the wrong provider id never matches.
	if err := core.ClaimForwardDispatchSend(ctx, runID, "prov-2", "tok-2"); !errors.Is(err, ErrDispatchClaimMiss) {
		t.Fatalf("wrong provider claim = %v, want ErrDispatchClaimMiss", err)
	}
}

func TestClaimForwardDispatchSend_ConcurrentClaimsHaveOneWinner(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	runID := "run-fwd-claim-race"

	seedForwardRun(t, core, runID, StateReverseInviteAccepted)

	if err := core.ReserveForwardDispatch(t.Context(), forwardReservationInput(runID, "prov-1")); err != nil {
		t.Fatalf("reserve: %v", err)
	}

	const racers = 8

	var wg sync.WaitGroup

	var wins atomic.Int32

	for range racers {
		wg.Add(1)

		go func() {
			defer wg.Done()

			if err := core.ClaimForwardDispatchSend(t.Context(), runID, "prov-1", "tok-race"); err == nil {
				wins.Add(1)
			}
		}()
	}

	wg.Wait()

	if got := wins.Load(); got != 1 {
		t.Fatalf("claim winners = %d, want exactly one", got)
	}
}

func TestMarkForwardDispatchRemoteSent_RequiresClaimedPermit(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-fwd-mark"

	seedForwardRun(t, core, runID, StateReverseInviteAccepted)

	if err := core.ReserveForwardDispatch(ctx, forwardReservationInput(runID, "prov-1")); err != nil {
		t.Fatalf("reserve: %v", err)
	}

	// A reserved-but-unclaimed reservation can never be stamped sent.
	markErr := core.MarkForwardDispatchRemoteSent(ctx, runID, "prov-1", "tok-1", "share-1")
	if !errors.Is(markErr, ErrDispatchConjunctMismatch) {
		t.Fatalf("mark reserved = %v, want ErrDispatchConjunctMismatch", markErr)
	}

	if err := core.ClaimForwardDispatchSend(ctx, runID, "prov-1", "tok-1"); err != nil {
		t.Fatalf("claim: %v", err)
	}

	if err := core.MarkForwardDispatchRemoteSent(ctx, runID, "prov-1", "tok-1", "share-1"); err != nil {
		t.Fatalf("mark: %v", err)
	}

	reservation := getReservation(t, core, runID)
	if reservation.Status != DispatchStatusRemoteSent {
		t.Fatalf("status = %q, want %q", reservation.Status, DispatchStatusRemoteSent)
	}

	if reservation.RemoteSentAt == nil {
		t.Fatal("remote_sent_at not stamped")
	}

	// A repeat stamp with the same identity is idempotent.
	if err := core.MarkForwardDispatchRemoteSent(ctx, runID, "prov-1", "tok-1", "share-1"); err != nil {
		t.Fatalf("repeat mark: %v", err)
	}

	// A stamp with a different provider id never matches.
	markErr = core.MarkForwardDispatchRemoteSent(ctx, runID, "prov-2", "tok-2", "share-2")
	if !errors.Is(markErr, ErrDispatchConjunctMismatch) {
		t.Fatalf("mark wrong provider = %v, want ErrDispatchConjunctMismatch", markErr)
	}
}

func TestCommitForwardShareSent_RequiresRemoteSent(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-fwd-commit-gate"

	seedForwardRun(t, core, runID, StateReverseInviteAccepted)

	if err := core.ReserveForwardDispatch(ctx, forwardReservationInput(runID, "prov-1")); err != nil {
		t.Fatalf("reserve: %v", err)
	}

	// The commit CAS never fires from dispatch_reserved.
	commitErr := core.CommitForwardShareSent(ctx, forwardCommitInput(runID))
	if !errors.Is(commitErr, ErrDispatchNotSent) {
		t.Fatalf("commit from reserved = %v, want ErrDispatchNotSent", commitErr)
	}

	requireState(t, core, runID, StateReverseInviteAccepted)

	if err := core.ClaimForwardDispatchSend(ctx, runID, "prov-1", "tok-1"); err != nil {
		t.Fatalf("claim: %v", err)
	}

	// Claimed is not sent either.
	commitErr = core.CommitForwardShareSent(ctx, forwardCommitInput(runID))
	if !errors.Is(commitErr, ErrDispatchNotSent) {
		t.Fatalf("commit from claimed = %v, want ErrDispatchNotSent", commitErr)
	}

	requireState(t, core, runID, StateReverseInviteAccepted)
}

func TestCommitForwardShareSent_CommitsWithAllConjuncts(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-fwd-commit"

	seedForwardRun(t, core, runID, StateReverseInviteAccepted)
	reserveClaimMark(t, core, runID)

	if err := core.CommitForwardShareSent(ctx, forwardCommitInput(runID)); err != nil {
		t.Fatalf("commit: %v", err)
	}

	requireState(t, core, runID, StateForwardShareSent)

	reservation := getReservation(t, core, runID)
	if reservation.Status != DispatchStatusCASCommitted {
		t.Fatalf("status = %q, want %q", reservation.Status, DispatchStatusCASCommitted)
	}

	if reservation.CASCommittedAt == nil {
		t.Fatal("cas_committed_at not stamped")
	}

	if reservation.OutgoingShareID == nil || *reservation.OutgoingShareID != "share-1" {
		t.Fatalf("outgoing_share_id = %v, want share-1", reservation.OutgoingShareID)
	}

	// A second commit never refires: the completed outbox row is no longer
	// remote_sent, so the strict predicate refuses it before touching the run.
	err := core.CommitForwardShareSent(ctx, forwardCommitInput(runID))
	if !errors.Is(err, ErrDispatchNotSent) {
		t.Fatalf("second commit = %v, want ErrDispatchNotSent", err)
	}

	requireState(t, core, runID, StateForwardShareSent)
}

func TestCommitForwardShareSent_ConjunctMismatch(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-fwd-conjunct"

	seedForwardRun(t, core, runID, StateReverseInviteAccepted)
	reserveClaimMark(t, core, runID)

	// A reservation snapshot that no longer matches the commit conjuncts
	// refuses the CAS.
	bad := forwardCommitInput(runID)
	bad.ShareWith = "mallory@peer.example"

	err := core.CommitForwardShareSent(ctx, bad)
	if !errors.Is(err, ErrDispatchConjunctMismatch) {
		t.Fatalf("commit with wrong recipient = %v, want ErrDispatchConjunctMismatch", err)
	}

	bad = forwardCommitInput(runID)
	bad.ProbeFilePath = "/tmp/other.txt"

	err = core.CommitForwardShareSent(ctx, bad)
	if !errors.Is(err, ErrDispatchConjunctMismatch) {
		t.Fatalf("commit with wrong probe path = %v, want ErrDispatchConjunctMismatch", err)
	}

	// A wire URI that does not equal the reservation's snapshot refuses the
	// CAS: the commit must prove the exact URI the dispatch sent.
	bad = forwardCommitInput(runID)
	bad.WebDAVURI = "https://peer.example/drifted/webdav-prov-1"

	err = core.CommitForwardShareSent(ctx, bad)
	if !errors.Is(err, ErrDispatchConjunctMismatch) {
		t.Fatalf("commit with drifted wire uri = %v, want ErrDispatchConjunctMismatch", err)
	}

	// A run pin that no longer matches misses the CAS.
	bad = forwardCommitInput(runID)
	bad.DesignatedShareWith = "mallory"

	err = core.CommitForwardShareSent(ctx, bad)
	if !errors.Is(err, ErrStateTransitionMiss) {
		t.Fatalf("commit with wrong designated pin = %v, want ErrStateTransitionMiss", err)
	}

	requireState(t, core, runID, StateReverseInviteAccepted)
}
