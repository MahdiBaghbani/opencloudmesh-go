// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package forwardshare_test

import (
	"net/http"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

// Local-path validation runs before the dispatch guard reserves the outbox
// row: an invalid path leaves no reservation behind, and the valid
// designated dispatch that follows reserves and sends normally.
func TestDispatch_InvalidLocalPathNeverStrandsReservation(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t, true)
	env.seedActiveRun(t, "run-dispatch-invalid-path", validatorcore.StateReverseInviteAccepted)

	// The designated triple with a path outside the allowed roots fails
	// local validation before any reservation exists.
	w := env.doCreate(t, shareBody(env.targetHost, testDesignated+"@"+env.targetHost, "/etc/passwd"))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("invalid path status = %d, want 400: %s", w.Code, w.Body.String())
	}

	if got := env.postCount.Load(); got != 0 {
		t.Fatalf("outbound POSTs = %d, want none", got)
	}

	if shares := env.listShares(t); len(shares) != 0 {
		t.Fatalf("stored shares = %d, want none", len(shares))
	}

	if _, err := env.store.GetDispatchReservation(t.Context(), "run-dispatch-invalid-path"); err == nil {
		t.Fatal("invalid path left a dispatch reservation behind")
	}

	// The valid designated dispatch reserves and sends normally.
	w = env.doCreate(t, env.designatedBody())
	if w.Code != http.StatusCreated {
		t.Fatalf("designated status = %d, want 201: %s", w.Code, w.Body.String())
	}

	if got := env.postCount.Load(); got != 1 {
		t.Fatalf("outbound POSTs = %d, want 1", got)
	}

	env.requireState(t, "run-dispatch-invalid-path", validatorcore.StateForwardShareSent)

	reservation := env.requireReservation(t, "run-dispatch-invalid-path")
	if reservation.Status != validatorcore.DispatchStatusCASCommitted {
		t.Fatalf("reservation status = %q, want %q", reservation.Status, validatorcore.DispatchStatusCASCommitted)
	}
}
