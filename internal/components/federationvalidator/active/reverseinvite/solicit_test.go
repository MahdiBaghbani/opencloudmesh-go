// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package reverseinvite_test

import (
	"errors"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/active/reverseinvite"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

func TestSolicitReverse_AdvancesAndIsIdempotent(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	ctx := t.Context()
	runID := "run-solicit-ok"

	env.seedRun(t, runID, validatorcore.StateInviteAccepted)
	env.bindBob(t, runID)

	if err := env.svc.SolicitReverse(ctx, runID); err != nil {
		t.Fatalf("solicit: %v", err)
	}

	env.requireState(t, runID, validatorcore.StateReverseAwaitingInvite)

	if err := env.svc.SolicitReverse(ctx, runID); err != nil {
		t.Fatalf("solicit retry: %v", err)
	}

	env.requireState(t, runID, validatorcore.StateReverseAwaitingInvite)
}

func TestSolicitReverse_HealsSolicitedCrashNotch(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	ctx := t.Context()
	runID := "run-solicit-notch"

	// Crash notch: solicited committed, the awaiting CAS never ran.
	env.seedRun(t, runID, validatorcore.StateReverseInviteSolicited)
	env.bindBob(t, runID)

	if err := env.svc.SolicitReverse(ctx, runID); err != nil {
		t.Fatalf("solicit heal: %v", err)
	}

	env.requireState(t, runID, validatorcore.StateReverseAwaitingInvite)
}

func TestSolicitReverse_FailsWhenBobNotBound(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	ctx := t.Context()
	runID := "run-solicit-no-bob"

	env.seedRun(t, runID, validatorcore.StateInviteAccepted)

	err := env.svc.SolicitReverse(ctx, runID)
	if !errors.Is(err, reverseinvite.ErrBobNotBound) {
		t.Fatalf("solicit = %v, want ErrBobNotBound", err)
	}

	env.requireState(t, runID, validatorcore.StateInviteAccepted)
}

func TestSolicitReverse_FailsWhenBobPartyMissing(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	ctx := t.Context()
	runID := "run-solicit-bob-gone"

	env.seedRun(t, runID, validatorcore.StateInviteAccepted)
	bobID := env.bindBob(t, runID)

	// Reuse-only: a bound but unmaterialized Bob must fail, never re-mint.
	if err := env.parties.Delete(ctx, bobID); err != nil {
		t.Fatalf("delete bob party: %v", err)
	}

	err := env.svc.SolicitReverse(ctx, runID)
	if !errors.Is(err, reverseinvite.ErrBobPartyMissing) {
		t.Fatalf("solicit = %v, want ErrBobPartyMissing", err)
	}

	env.requireState(t, runID, validatorcore.StateInviteAccepted)
}
