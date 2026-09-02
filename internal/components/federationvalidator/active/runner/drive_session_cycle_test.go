// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package runner

import (
	"context"
	"net/http"
	"testing"
	"time"

	outgoingshares "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api/outgoing/shares"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

// TestDriveSessionCycle_DispatchRetryWaitAfterKickDoesNotStackHandleBackoff
// proves a no-op dispatch retry wait is checked before permit acquire.
// Kick resets handle park backoff only; the next cycle must not take a
// permit or record a new handle delay on top of the real retry wait.
func TestDriveSessionCycle_DispatchRetryWaitAfterKickDoesNotStackHandleBackoff(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0)
	out := &cycleOutgoing{err: &outgoingshares.ReceiverStatusError{Status: http.StatusInternalServerError}}
	env := newDriveEnv(t, &driveInvites{}, func() time.Time { return now }, 0)
	env.runner.BindOutgoing(out)

	runID := "run-cycle-retry-wait"
	seedDriveRun(t, env.store, runID, "retry.example", validatorcore.StateReverseInviteAccepted)
	mustUpdate(t, env.store, runID, "designated_share_with", "omar")

	h := newCycleHandle(t, env.runner, runID)
	env.runner.handlesMu.Lock()
	env.runner.handles[runID] = h
	env.runner.handlesMu.Unlock()

	if !env.runner.driveSessionCycle(h) {
		t.Fatal("first cycle exited")
	}

	if out.calls != 1 {
		t.Fatalf("CreateAsUser calls = %d, want 1", out.calls)
	}

	if len(env.runner.drivePermits) != 0 {
		t.Fatalf("first cycle leaked %d permits", len(env.runner.drivePermits))
	}

	if wait := h.backoffWait(now); wait <= 0 {
		t.Fatal("first cycle did not record handle park backoff")
	}

	// Kick wakes the handle; the session loop resets park backoff
	// on that wake. Drive the same reset here so the next cycle
	// sees a pending dispatch wait with a zero handle delay.
	env.runner.Kick()
	h.resetBackoff()

	if wait := h.backoffWait(now); wait > 0 {
		t.Fatalf("Kick/reset left handle park backoff %s", wait)
	}

	if !env.runner.driveSessionCycle(h) {
		t.Fatal("retry-wait cycle exited")
	}

	if out.calls != 1 {
		t.Fatalf("retry-wait cycle dispatched: calls = %d, want 1", out.calls)
	}

	if len(env.runner.drivePermits) != 0 {
		t.Fatalf("retry-wait cycle held %d permits, want 0", len(env.runner.drivePermits))
	}

	if wait := h.backoffWait(now); wait > 0 {
		t.Fatalf("retry-wait cycle stacked handle backoff %s", wait)
	}

	if got := env.runner.parkDuration(h); got != env.runner.reapInterval() {
		t.Fatalf("parkDuration = %s, want reap interval %s", got, env.runner.reapInterval())
	}
}

type cycleOutgoing struct {
	err   error
	calls int
}

func (s *cycleOutgoing) CreateAsUser(
	_ context.Context,
	_ *identity.User,
	_ sharesoutgoing.OutgoingShareRequest,
) (*sharesoutgoing.OutgoingShare, error) {
	s.calls++

	if s.err != nil {
		return nil, s.err
	}

	return &sharesoutgoing.OutgoingShare{ShareID: "share-1"}, nil
}
