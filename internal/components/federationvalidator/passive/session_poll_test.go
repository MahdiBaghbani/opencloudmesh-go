// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

func TestHandleSession_TerminalStatesOmitNextInstruction(t *testing.T) {
	t.Parallel()

	for _, state := range []string{
		validatorcore.StateTerminalPass,
		validatorcore.StateTerminalFail,
		validatorcore.StateInterrupted,
	} {
		t.Run(state, func(t *testing.T) {
			t.Parallel()

			store := openHandlerTestStore(t)
			h := NewHandler(store, nil)
			now := time.Now().Unix()
			finishedAt := now + 1
			runID := "run-" + state

			seedSessionRow(t, store, &validatorcore.TestRun{
				TestRunID:  runID,
				State:      state,
				TargetHost: "peer.example",
				FinishedAt: &finishedAt,
				CreatedAt:  now,
				UpdatedAt:  finishedAt,
			})

			payload := pollSession(t, h, runID)

			assertExactKeys(t, payload, []string{"state", "ts"})
		})
	}
}

func TestHandleSession_TerminalFailPublishesFailModeLabel(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	now := time.Now().Unix()
	finishedAt := now + 1
	runID := "run-fail-mode"
	reason := validatorcore.ReasonPassiveProbeFailed

	seedSessionRow(t, store, &validatorcore.TestRun{
		TestRunID:      runID,
		State:          validatorcore.StateTerminalFail,
		TargetHost:     "peer.example",
		TerminalReason: &reason,
		FinishedAt:     &finishedAt,
		CreatedAt:      now,
		UpdatedAt:      finishedAt,
	})

	rec := doPoll(t, h, runID)
	body := rec.Body.String()

	if strings.Contains(body, validatorcore.ReasonPassiveProbeFailed) {
		t.Fatalf("poll echoed raw terminal reason token: %s", body)
	}

	var payload map[string]json.RawMessage
	if err := json.NewDecoder(strings.NewReader(body)).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}

	assertExactKeys(t, payload, []string{"state", "ts", "failModeLabel"})

	var label string
	if err := json.Unmarshal(payload["failModeLabel"], &label); err != nil {
		t.Fatalf("failModeLabel: %v", err)
	}

	if label != "Passive probe failed" {
		t.Fatalf("failModeLabel = %q, want %q", label, "Passive probe failed")
	}
}

func TestHandleSession_PollDoesNotMutateSession(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	ctx := t.Context()
	now := time.Now().Unix()
	runID := "run-readonly"

	seedSessionRow(t, store, &validatorcore.TestRun{
		TestRunID:  runID,
		State:      validatorcore.StatePassiveComplete,
		TargetHost: "peer.example",
		CreatedAt:  now,
		UpdatedAt:  now + 7,
	})

	before, err := store.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("load before poll: %v", err)
	}

	pollSession(t, h, runID)

	after, err := store.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("load after poll: %v", err)
	}

	if !reflect.DeepEqual(before, after) {
		t.Fatalf("poll mutated session row: before %+v, after %+v", before, after)
	}
}

func TestHandleSession_PollOmitsSensitiveSessionFields(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	now := time.Now().Unix()
	runID := "run-secrets"

	bobUserID := "probe-user-id-marker"
	reverseInvite := "reverse-invite-string-marker"
	designatedShareWith := "validator-party-email@example.com"
	reverseShareProviderID := "bob-cloudid-marker"

	seedSessionRow(t, store, &validatorcore.TestRun{
		TestRunID:              runID,
		IsActive:               true,
		State:                  validatorcore.StateReverseAwaitingInvite,
		TargetHost:             "peer.example",
		BobUserID:              &bobUserID,
		ReverseInviteToken:     &reverseInvite,
		DesignatedShareWith:    &designatedShareWith,
		ReverseShareProviderID: &reverseShareProviderID,
		CreatedAt:              now,
		UpdatedAt:              now,
	})

	rec := doPoll(t, h, runID)
	body := rec.Body.String()

	for _, secret := range []string{bobUserID, reverseInvite, designatedShareWith, reverseShareProviderID} {
		if strings.Contains(body, secret) {
			t.Fatalf("poll response leaks %q: %s", secret, body)
		}
	}

	var payload map[string]json.RawMessage
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}

	assertExactKeys(t, payload, []string{"state", "ts", "nextInstruction"})

	if next := pollNextInstruction(t, payload); next != "paste_s2" {
		t.Fatalf("nextInstruction = %q, want %q", next, "paste_s2")
	}
}

func TestHandleSession_UnknownID404(t *testing.T) {
	t.Parallel()

	h := NewHandler(openHandlerTestStore(t), nil)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/session/missing-run", nil)
	rec := httptest.NewRecorder()
	newSessionTestRouter(t, h).ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}

	var payload map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if payload["error"] != validatorcore.CodeSessionNotFound {
		t.Fatalf("error = %q, want %q", payload["error"], validatorcore.CodeSessionNotFound)
	}
}

func TestHandleSession_MethodNotAllowed(t *testing.T) {
	t.Parallel()

	h := NewHandler(openHandlerTestStore(t), nil)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/session/run-1", nil)
	rec := httptest.NewRecorder()
	h.HandleSession(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

func TestHandleStop_UnknownIDStill409(t *testing.T) {
	t.Parallel()

	h := NewHandler(openHandlerTestStore(t), nil)

	body := mustJSON(t, map[string]string{"id": "missing-run"})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/stop", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.HandleStop(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}

	var payload map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if payload["error"] != validatorcore.CodeSessionNotFound {
		t.Fatalf("error = %q, want %q", payload["error"], validatorcore.CodeSessionNotFound)
	}
}

func TestMountPlaneARoutes_SessionSuffixExtraNotRouted(t *testing.T) {
	t.Parallel()

	r := newPlaneATestRouter(t)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/session/run-1/extra", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for suffix path", rec.Code)
	}
}
