// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package forwardshare_test

import (
	"errors"
	"net/http"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

// requireRefused asserts the refusal contract: the response is 403, no
// outbound POST happened, no local outgoing share row exists, and the
// refusal left no dispatch reservation behind for the run.
func requireRefused(t *testing.T, env *testEnv, code int, runID string) {
	t.Helper()

	if code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", code, http.StatusForbidden)
	}

	if got := env.postCount.Load(); got != 0 {
		t.Fatalf("outbound POSTs = %d, want none", got)
	}

	if got := len(env.listShares(t)); got != 0 {
		t.Fatalf("stored shares = %d, want none", got)
	}

	requireNoReservation(t, env, runID)
}

// requireNoReservation asserts the run has no dispatch reservation row.
func requireNoReservation(t *testing.T, env *testEnv, runID string) {
	t.Helper()

	_, err := env.store.GetDispatchReservation(t.Context(), runID)
	if !errors.Is(err, validatorcore.ErrDispatchReservationNotFound) {
		t.Fatalf("dispatch reservation after refusal = %v, want not found", err)
	}
}

func TestGuard_NoActiveRunPreservesGenericBehavior(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t, true)

	w := env.doCreate(t, env.designatedBody())
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", w.Code, w.Body.String())
	}

	if got := env.postCount.Load(); got != 1 {
		t.Fatalf("outbound POSTs = %d, want 1", got)
	}

	if got := len(env.listShares(t)); got != 1 {
		t.Fatalf("stored shares = %d, want 1", got)
	}
}

func TestGuard_NilHookPreservesGenericBehavior(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t, false)

	w := env.doCreate(t, env.designatedBody())
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", w.Code, w.Body.String())
	}

	if got := env.postCount.Load(); got != 1 {
		t.Fatalf("outbound POSTs = %d, want 1", got)
	}
}

func TestGuard_RefusesNonDesignatedRecipient(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t, true)
	env.seedActiveRun(t, "run-guard-recipient", validatorcore.StateReverseInviteAccepted)

	body := shareBody(env.targetHost, "mallory@"+env.targetHost, env.probePath)
	w := env.doCreate(t, body)

	requireRefused(t, env, w.Code, "run-guard-recipient")
	env.requireState(t, "run-guard-recipient", validatorcore.StateReverseInviteAccepted)
}

func TestGuard_RefusesNonDesignatedReceiverHost(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t, true)
	env.seedActiveRun(t, "run-guard-host", validatorcore.StateReverseInviteAccepted)

	// The designated recipient string at a different host is still not the
	// designated dispatch; refusal happens before any outbound call, so the
	// host never needs to answer.
	body := shareBody("other.example:9443", testDesignated+"@other.example:9443", env.probePath)
	w := env.doCreate(t, body)

	requireRefused(t, env, w.Code, "run-guard-host")
}

func TestGuard_RefusesNonDesignatedPath(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t, true)
	env.seedActiveRun(t, "run-guard-path", validatorcore.StateReverseInviteAccepted)

	// First dispatch claims the probe file; a second file to the same
	// designated recipient is not the designated dispatch.
	w := env.doCreate(t, env.designatedBody())
	if w.Code != http.StatusCreated {
		t.Fatalf("designated status = %d, want 201: %s", w.Code, w.Body.String())
	}

	otherPath := createProbeFile(t)
	body := shareBody(env.targetHost, testDesignated+"@"+env.targetHost, otherPath)
	w = env.doCreate(t, body)

	if w.Code != http.StatusForbidden {
		t.Fatalf("second path status = %d, want 403: %s", w.Code, w.Body.String())
	}

	if got := env.postCount.Load(); got != 1 {
		t.Fatalf("outbound POSTs = %d, want 1", got)
	}

	if got := len(env.listShares(t)); got != 1 {
		t.Fatalf("stored shares = %d, want 1", got)
	}

	// The refusal left the designated dispatch's reservation untouched.
	reservation := env.requireReservation(t, "run-guard-path")
	if reservation.Status != validatorcore.DispatchStatusCASCommitted {
		t.Fatalf("reservation status = %q, want %q", reservation.Status, validatorcore.DispatchStatusCASCommitted)
	}
}

// An unbound admin submitting the exact designated triple is still refused:
// only the session's own dispatching party may dispatch while its run is
// active, and refusal happens before any persistence or outbound call.
func TestGuard_RefusesUnboundSuperadmin(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t, true)
	env.seedActiveRun(t, "run-guard-admin", validatorcore.StateReverseInviteAccepted)

	env.user.Store(&identity.User{ID: "user-root", Username: "root", Role: "admin"})

	w := env.doCreate(t, env.designatedBody())

	requireRefused(t, env, w.Code, "run-guard-admin")
}

// An unbound user cannot replay an existing reservation either: after the
// designated party dispatched, the same request from another user is refused
// without a second remote share.
func TestGuard_RefusesUnboundReplay(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t, true)
	env.seedActiveRun(t, "run-guard-replay", validatorcore.StateReverseInviteAccepted)

	w := env.doCreate(t, env.designatedBody())
	if w.Code != http.StatusCreated {
		t.Fatalf("designated status = %d, want 201: %s", w.Code, w.Body.String())
	}

	env.user.Store(&identity.User{ID: "user-intruder", Username: "intruder"})

	w = env.doCreate(t, env.designatedBody())
	if w.Code != http.StatusForbidden {
		t.Fatalf("replay status = %d, want 403: %s", w.Code, w.Body.String())
	}

	if got := env.postCount.Load(); got != 1 {
		t.Fatalf("outbound POSTs = %d, want 1", got)
	}

	if got := len(env.listShares(t)); got != 1 {
		t.Fatalf("stored shares = %d, want 1", got)
	}

	// The refusal left the designated dispatch's reservation untouched.
	reservation := env.requireReservation(t, "run-guard-replay")
	if reservation.Status != validatorcore.DispatchStatusCASCommitted {
		t.Fatalf("reservation status = %q, want %q", reservation.Status, validatorcore.DispatchStatusCASCommitted)
	}
}

func TestGuard_RefusesBoundRecipient(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t, true)
	env.seedActiveRun(t, "run-guard-bob", validatorcore.StateReverseInviteAccepted)

	// The bound recipient is refused even when asking for the designated
	// dispatch identity.
	bob := env.bindRecipient(t, "run-guard-bob")
	env.user.Store(bob)

	w := env.doCreate(t, env.designatedBody())

	requireRefused(t, env, w.Code, "run-guard-bob")
}

func TestGuard_RefusesWhenRunNotAwaitingDispatch(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t, true)

	// An active run that has not completed the reverse-invite leg has no
	// designated dispatch yet, so even the designated-looking share refuses.
	env.seedActiveRun(t, "run-guard-early", validatorcore.StateActiveRunning)

	w := env.doCreate(t, env.designatedBody())

	requireRefused(t, env, w.Code, "run-guard-early")
	env.requireState(t, "run-guard-early", validatorcore.StateActiveRunning)
}
