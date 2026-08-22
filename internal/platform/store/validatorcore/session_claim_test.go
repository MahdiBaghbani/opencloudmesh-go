// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"errors"
	"sync"
	"testing"
)

func TestClaimOutgoingInvite_PayloadLoadFailureDoesNotConsume(t *testing.T) {
	t.Parallel()

	core := openMigratedProductionCore(t)
	ctx := t.Context()
	runID := "run-claim-load-fail"

	seedReverseInviteRun(t, core, runID, StateActiveRunning)

	if err := core.MintOutgoingInvite(ctx, runID, sampleOutgoingMint("invite-1", "token-1", runID)); err != nil {
		t.Fatalf("mint: %v", err)
	}

	injected := errors.New("injected payload load failure")

	core.SetClaimPayloadLoadHook(func() error {
		core.SetClaimPayloadLoadHook(nil)

		return injected
	})

	_, err := core.ClaimOutgoingInvite(ctx, runID)
	if !errors.Is(err, injected) {
		t.Fatalf("first claim = %v, want injected payload load failure", err)
	}

	requireNoS1Claim(t, core, runID)

	first, err := core.ClaimOutgoingInvite(ctx, runID)
	if err != nil {
		t.Fatalf("retry claim: %v", err)
	}

	if first.InviteString != "invite-string-invite-1" {
		t.Fatalf("inviteString = %q, want invite-string-invite-1", first.InviteString)
	}

	_, err = core.ClaimOutgoingInvite(ctx, runID)
	if !errors.Is(err, ErrInviteAlreadyClaimed) {
		t.Fatalf("second claim = %v, want ErrInviteAlreadyClaimed", err)
	}
}

func TestClaimOutgoingInvite_FirstWinsAndLaterIsAlreadyClaimed(t *testing.T) {
	t.Parallel()

	core := openMigratedProductionCore(t)
	ctx := t.Context()
	runID := "run-claim-once"

	seedReverseInviteRun(t, core, runID, StateActiveRunning)

	if err := core.MintOutgoingInvite(ctx, runID, sampleOutgoingMint("invite-1", "token-1", runID)); err != nil {
		t.Fatalf("mint: %v", err)
	}

	first, err := core.ClaimOutgoingInvite(ctx, runID)
	if err != nil {
		t.Fatalf("first claim: %v", err)
	}

	if first.InviteString != "invite-string-invite-1" {
		t.Fatalf("inviteString = %q, want invite-string-invite-1", first.InviteString)
	}

	if first.IssuerFQDN != "local.example" {
		t.Fatalf("issuer = %q, want local.example", first.IssuerFQDN)
	}

	if first.PasteTargetHost != "peer.example" {
		t.Fatalf("paste host = %q, want peer.example", first.PasteTargetHost)
	}

	if first.PasteTargetOrigin != "https://peer.example" {
		t.Fatalf("paste origin = %q, want https://peer.example", first.PasteTargetOrigin)
	}

	if first.ExpiresAt.IsZero() {
		t.Fatal("expiresAt is zero")
	}

	_, err = core.ClaimOutgoingInvite(ctx, runID)
	if !errors.Is(err, ErrInviteAlreadyClaimed) {
		t.Fatalf("second claim = %v, want ErrInviteAlreadyClaimed", err)
	}
}

func TestClaimOutgoingInvite_PostAcceptSecondClaimIsAlreadyClaimed(t *testing.T) {
	t.Parallel()

	core := openMigratedProductionCore(t)
	ctx := t.Context()
	runID := "run-claim-after-accept"

	seedReverseInviteRun(t, core, runID, StateActiveRunning)

	if err := core.MintOutgoingInvite(ctx, runID, sampleOutgoingMint("invite-1", "token-1", runID)); err != nil {
		t.Fatalf("mint: %v", err)
	}

	if _, err := core.ClaimOutgoingInvite(ctx, runID); err != nil {
		t.Fatalf("first claim: %v", err)
	}

	if err := core.RecordOutgoingInviteAccepted(ctx, runID, "alice"); err != nil {
		t.Fatalf("accept: %v", err)
	}

	_, err := core.ClaimOutgoingInvite(ctx, runID)
	if !errors.Is(err, ErrInviteAlreadyClaimed) {
		t.Fatalf("post-accept claim = %v, want ErrInviteAlreadyClaimed", err)
	}
}

func TestClaimOutgoingInvite_NotMintedIsNotReady(t *testing.T) {
	t.Parallel()

	core := openMigratedProductionCore(t)
	ctx := t.Context()
	runID := "run-claim-not-ready"

	seedReverseInviteRun(t, core, runID, StateActiveRunning)

	_, err := core.ClaimOutgoingInvite(ctx, runID)
	if !errors.Is(err, ErrSessionNotReady) {
		t.Fatalf("claim = %v, want ErrSessionNotReady", err)
	}
}

func TestClaimOutgoingInvite_UnknownSession(t *testing.T) {
	t.Parallel()

	core := openMigratedProductionCore(t)

	_, err := core.ClaimOutgoingInvite(t.Context(), "run-missing")
	if !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("claim = %v, want ErrSessionNotFound", err)
	}
}

func TestClaimOutgoingInvite_ConcurrentSingleWinner(t *testing.T) {
	t.Parallel()

	core := openMigratedProductionCore(t)
	ctx := t.Context()
	runID := "run-claim-race"

	seedReverseInviteRun(t, core, runID, StateActiveRunning)

	if err := core.MintOutgoingInvite(ctx, runID, sampleOutgoingMint("invite-1", "token-1", runID)); err != nil {
		t.Fatalf("mint: %v", err)
	}

	const workers = 8

	var wg sync.WaitGroup

	errs := make([]error, workers)

	for i := range workers {
		wg.Add(1)

		go func() {
			defer wg.Done()

			_, errs[i] = core.ClaimOutgoingInvite(ctx, runID)
		}()
	}

	wg.Wait()

	wins := 0

	for _, err := range errs {
		if err == nil {
			wins++

			continue
		}

		if !errors.Is(err, ErrInviteAlreadyClaimed) {
			t.Fatalf("loser error = %v, want ErrInviteAlreadyClaimed", err)
		}
	}

	if wins != 1 {
		t.Fatalf("winners = %d, want exactly 1", wins)
	}

	run, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if run.S1ClaimedAt == nil {
		t.Fatal("s1_claimed_at is nil after concurrent claim")
	}
}
