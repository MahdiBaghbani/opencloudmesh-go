// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

func seedActiveRun(t *testing.T, store *validatorcore.Core, runID, state string, isActive bool) {
	t.Helper()

	now := time.Now().Unix()

	seedSessionRow(t, store, &validatorcore.TestRun{
		TestRunID:  runID,
		IsActive:   isActive,
		State:      state,
		TargetHost: "peer.example",
		CreatedAt:  now,
		UpdatedAt:  now,
	})
}

func newPollHealRouter(t *testing.T, store *validatorcore.Core, opener ReverseWaitOpener) chi.Router {
	t.Helper()

	r := chi.NewRouter()
	MountPlaneARoutesWithHeal(
		r,
		NewHandler(store, nil),
		nil,
		opener,
	)

	return r
}

func pollStateViaRouter(t *testing.T, r chi.Router, runID string) (string, int) {
	t.Helper()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/session/"+runID, nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	var payload struct {
		State string `json:"state"`
	}

	if rec.Code == http.StatusOK {
		if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
			t.Fatalf("decode: %v", err)
		}
	}

	return payload.State, rec.Code
}

func TestHandleSession_PollHealInvokesOpenerWhenCapabilityExercise(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	seedActiveRun(t, store, "run-heal-open", validatorcore.StateCapabilityExercise, true)

	called := 0

	r := newPollHealRouter(t, store, func(ctx context.Context, testRunID string) error {
		called++

		// Mirror the real opener: the wait open moves the run out of the
		// capability exercise, and the poll must report the state it left.
		res := store.DB().WithContext(ctx).Model(&validatorcore.TestRun{}).
			Where("test_run_id = ?", testRunID).
			Updates(map[string]any{"state": validatorcore.StateReverseAwaitingShare, "updated_at": time.Now().Unix()})

		return res.Error
	})

	state, code := pollStateViaRouter(t, r, "run-heal-open")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}

	if state != validatorcore.StateReverseAwaitingShare {
		t.Fatalf("state = %q, want %q (the poll reports the state the open left)",
			state, validatorcore.StateReverseAwaitingShare)
	}

	if called != 1 {
		t.Fatalf("opener calls = %d, want 1", called)
	}
}

func TestHandleSession_PollHealSkipsNonCapabilityStates(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	seedActiveRun(t, store, "run-heal-skip", validatorcore.StateReverseAwaitingShare, true)

	called := false

	r := newPollHealRouter(t, store, func(_ context.Context, _ string) error {
		called = true

		return nil
	})

	state, code := pollStateViaRouter(t, r, "run-heal-skip")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}

	if state != validatorcore.StateReverseAwaitingShare {
		t.Fatalf("state = %q, want %q", state, validatorcore.StateReverseAwaitingShare)
	}

	if called {
		t.Error("opener must not run when the loaded session already left the capability exercise")
	}
}

func TestHandleSession_PollHealSkipsInactiveSession(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	seedActiveRun(t, store, "run-heal-inactive", validatorcore.StateCapabilityExercise, false)

	called := false

	r := newPollHealRouter(t, store, func(_ context.Context, _ string) error {
		called = true

		return nil
	})

	state, code := pollStateViaRouter(t, r, "run-heal-inactive")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}

	if state != validatorcore.StateCapabilityExercise {
		t.Fatalf("state = %q, want %q", state, validatorcore.StateCapabilityExercise)
	}

	if called {
		t.Error("opener must not run for an inactive session")
	}
}

func TestHandleSession_PollHealErrorStillServesState(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	seedActiveRun(t, store, "run-heal-error", validatorcore.StateCapabilityExercise, true)

	r := newPollHealRouter(t, store, func(_ context.Context, _ string) error {
		return errors.New("storage unavailable")
	})

	state, code := pollStateViaRouter(t, r, "run-heal-error")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}

	if state != validatorcore.StateCapabilityExercise {
		t.Fatalf("state = %q, want %q (a heal failure never breaks the poll)",
			state, validatorcore.StateCapabilityExercise)
	}
}

func TestHandleSession_PollHealUnknownSessionKeepsNotFound(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)

	called := false

	r := newPollHealRouter(t, store, func(_ context.Context, _ string) error {
		called = true

		return nil
	})

	_, code := pollStateViaRouter(t, r, "run-heal-missing")
	if code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (the heal wrapper must not mask the poll error)", code)
	}

	if called {
		t.Error("opener must not run for a session the store cannot load")
	}
}

func TestHandleSession_NoOpenerKeepsPlainPoll(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	seedActiveRun(t, store, "run-heal-none", validatorcore.StateCapabilityExercise, true)

	r := chi.NewRouter()
	MountPlaneARoutes(r, NewHandler(store, nil), nil)

	state, code := pollStateViaRouter(t, r, "run-heal-none")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}

	if state != validatorcore.StateCapabilityExercise {
		t.Fatalf("state = %q, want %q", state, validatorcore.StateCapabilityExercise)
	}
}
