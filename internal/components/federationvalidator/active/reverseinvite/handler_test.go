// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package reverseinvite_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
	invitesincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/incoming"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

func (e *testEnv) pasteRouter() *chi.Mux {
	r := chi.NewRouter()
	r.Post("/api/session/{id}/reverse-invite", e.svc.HandleReverseInvite)

	return r
}

func pasteInvite(t *testing.T, r *chi.Mux, runID, inviteString string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequestWithContext(
		t.Context(), http.MethodPost,
		"/api/session/"+runID+"/reverse-invite",
		strings.NewReader(`{"inviteString":"`+inviteString+`"}`),
	)
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	return rec
}

// requireReverseAcceptedRun proves the post-accept world for the run: state
// and token pin, the exact correlation row, the accepted incoming invite, and
// exactly one accept evidence row. It returns the accepted invite.
func requireReverseAcceptedRun(
	t *testing.T,
	env *testEnv,
	runID, bobID, token string,
) *invitesincoming.IncomingInvite {
	t.Helper()

	env.requireState(t, runID, validatorcore.StateReverseInviteAccepted)

	run, err := env.store.GetTestRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if run.ReverseInviteToken == nil || *run.ReverseInviteToken != token {
		t.Fatalf("reverse_invite_token = %v, want %s", run.ReverseInviteToken, token)
	}

	corr, err := env.store.GetShareCorrelation(t.Context(), runID, validatorcore.RoleIncomingInvite, validatorcore.LocalIdentityB)
	if err != nil {
		t.Fatalf("GetShareCorrelation: %v", err)
	}

	if corr.ProviderID != token {
		t.Fatalf("provider id = %q, want %s", corr.ProviderID, token)
	}

	if corr.SenderHost != testTargetHost {
		t.Fatalf("sender host = %q, want %q", corr.SenderHost, testTargetHost)
	}

	if corr.InviteID == nil || *corr.InviteID == "" {
		t.Fatal("correlation invite id is empty")
	}

	invite, err := env.incoming.GetByIDForRecipientUserID(t.Context(), *corr.InviteID, bobID)
	if err != nil {
		t.Fatalf("load incoming invite: %v", err)
	}

	if invite.Status != invites.InviteStatusAccepted {
		t.Fatalf("incoming status = %q, want accepted", invite.Status)
	}

	if got := env.countEvidence(t, runID); got != 1 {
		t.Fatalf("evidence rows = %d, want 1", got)
	}

	return invite
}

func TestHandleReverseInvite_ImportAndAcceptInOneRequest(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	runID := "run-paste-happy"

	env.seedRun(t, runID, validatorcore.StateReverseAwaitingInvite)
	bobID := env.bindBob(t, runID)

	inviteString := invites.BuildInviteString("reverse-token-1", testTargetHost)

	rec := pasteInvite(t, env.pasteRouter(), runID, inviteString)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}

	invite := requireReverseAcceptedRun(t, env, runID, bobID, "reverse-token-1")

	if invite.SenderUserID != "sender@peer.example" {
		t.Fatalf("sender user id = %q, want sender@peer.example", invite.SenderUserID)
	}

	if env.poster.calls != 1 {
		t.Fatalf("poster calls = %d, want 1", env.poster.calls)
	}

	// The response must not leak the invite string or Bob's identity.
	if strings.Contains(rec.Body.String(), inviteString) || strings.Contains(rec.Body.String(), bobID) {
		t.Fatalf("response leaks sensitive material: %s", rec.Body.String())
	}
}

func TestHandleReverseInvite_WrongTargetHostRejected(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	ctx := t.Context()
	runID := "run-paste-wrong-host"

	env.seedRun(t, runID, validatorcore.StateInviteAccepted)
	bobID := env.bindBob(t, runID)

	inviteString := invites.BuildInviteString("reverse-token-x", "other-host.example")

	rec := pasteInvite(t, env.pasteRouter(), runID, inviteString)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", rec.Code)
	}

	env.requireState(t, runID, validatorcore.StateInviteAccepted)

	if _, err := env.store.GetShareCorrelation(ctx, runID, validatorcore.RoleIncomingInvite, validatorcore.LocalIdentityB); err == nil {
		t.Fatal("correlation row exists after wrong-host rejection")
	}

	if _, err := env.incoming.GetByTokenForRecipientUserID(ctx, "reverse-token-x", bobID); err == nil {
		t.Fatal("incoming invite stored after wrong-host rejection")
	}

	if env.poster.calls != 0 {
		t.Fatalf("poster calls = %d, want 0", env.poster.calls)
	}
}

func TestHandleReverseInvite_DifferentTokenAfterOccupancyRejected(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	runID := "run-paste-second-token"

	env.seedRun(t, runID, validatorcore.StateReverseAwaitingInvite)
	env.bindBob(t, runID)

	first := invites.BuildInviteString("reverse-token-1", testTargetHost)
	if rec := pasteInvite(t, env.pasteRouter(), runID, first); rec.Code != http.StatusOK {
		t.Fatalf("first paste status = %d, want 200", rec.Code)
	}

	second := invites.BuildInviteString("reverse-token-2", testTargetHost)

	rec := pasteInvite(t, env.pasteRouter(), runID, second)
	if rec.Code != http.StatusConflict {
		t.Fatalf("second paste status = %d, want 409", rec.Code)
	}

	env.requireState(t, runID, validatorcore.StateReverseInviteAccepted)

	run, err := env.store.GetTestRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if run.ReverseInviteToken == nil || *run.ReverseInviteToken != "reverse-token-1" {
		t.Fatalf("reverse_invite_token = %v, want first token wins", run.ReverseInviteToken)
	}

	if got := env.countEvidence(t, runID); got != 1 {
		t.Fatalf("evidence rows = %d, want 1", got)
	}
}

func TestHandleReverseInvite_RetryAfterImportNotch(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	ctx := t.Context()
	runID := "run-paste-notch"

	env.seedRun(t, runID, validatorcore.StateReverseAwaitingInvite)
	bobID := env.bindBob(t, runID)

	// Simulate the crash notch: the incoming invite row and the paste
	// committed, but product accept never ran.
	inviteString := invites.BuildInviteString("reverse-token-1", testTargetHost)

	invite, err := env.createIncoming(t, inviteString, "reverse-token-1", testTargetHost, bobID)
	if err != nil {
		t.Fatalf("create incoming: %v", err)
	}

	incomingID := invite.ID

	if importErr := env.store.ImportReverseInvite(ctx, runID, "reverse-token-1", incomingID); importErr != nil {
		t.Fatalf("import: %v", importErr)
	}

	env.requireState(t, runID, validatorcore.StateReverseInviteAccepted)

	rec := pasteInvite(t, env.pasteRouter(), runID, inviteString)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 after import (body %s)", rec.Code, rec.Body.String())
	}

	env.requireState(t, runID, validatorcore.StateReverseInviteAccepted)

	corr, err := env.store.GetShareCorrelation(ctx, runID, validatorcore.RoleIncomingInvite, validatorcore.LocalIdentityB)
	if err != nil {
		t.Fatalf("GetShareCorrelation: %v", err)
	}

	if corr.InviteID == nil || *corr.InviteID != incomingID {
		t.Fatalf("correlation invite id = %v, want %q", corr.InviteID, incomingID)
	}

	if got := env.countEvidence(t, runID); got != 1 {
		t.Fatalf("evidence rows = %d, want 1", got)
	}

	if env.poster.calls != 0 {
		t.Fatalf("poster calls = %d, want 0", env.poster.calls)
	}
}

func TestHandleReverseInvite_RemoteConflictHealsAsSuccess(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	runID := "run-paste-remote-409"

	env.seedRun(t, runID, validatorcore.StateReverseAwaitingInvite)
	env.bindBob(t, runID)

	// The sender already accepted this invite: 409 with a decodable identity
	// is idempotent success.
	env.poster.status = http.StatusConflict
	env.poster.body = `{"userID":"sender@peer.example","email":"s@example","name":"Sender"}`

	inviteString := invites.BuildInviteString("reverse-token-1", testTargetHost)

	rec := pasteInvite(t, env.pasteRouter(), runID, inviteString)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}

	env.requireState(t, runID, validatorcore.StateReverseInviteAccepted)

	if got := env.countEvidence(t, runID); got != 1 {
		t.Fatalf("evidence rows = %d, want 1", got)
	}
}

func TestHandleReverseInvite_RemoteFailureLeavesImportNotch(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	runID := "run-paste-remote-500"

	env.seedRun(t, runID, validatorcore.StateReverseAwaitingInvite)
	env.bindBob(t, runID)

	env.poster.status = http.StatusInternalServerError
	env.poster.body = `{"message":"boom"}`

	inviteString := invites.BuildInviteString("reverse-token-1", testTargetHost)

	rec := pasteInvite(t, env.pasteRouter(), runID, inviteString)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}

	// The paste is durable: state is already accepted with sharing evidence.
	// Later-state retry paste is rejected and must not call the peer again.
	env.requireState(t, runID, validatorcore.StateReverseInviteAccepted)

	if got := env.countEvidence(t, runID); got != 1 {
		t.Fatalf("evidence rows = %d, want 1 from the paste", got)
	}

	posterCalls := env.poster.calls

	rec = pasteInvite(t, env.pasteRouter(), runID, inviteString)
	if rec.Code != http.StatusConflict {
		t.Fatalf("retry status = %d, want 409 (body %s)", rec.Code, rec.Body.String())
	}

	env.requireState(t, runID, validatorcore.StateReverseInviteAccepted)

	if got := env.countEvidence(t, runID); got != 1 {
		t.Fatalf("evidence rows after retry = %d, want 1", got)
	}

	if env.poster.calls != posterCalls {
		t.Fatalf("poster calls after retry = %d, want %d", env.poster.calls, posterCalls)
	}
}

func TestHandleReverseInvite_EarlyPasteBeforeSolicitRejected(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	ctx := t.Context()
	runID := "run-paste-too-early"

	env.seedRun(t, runID, validatorcore.StateInviteAccepted)
	bobID := env.bindBob(t, runID)

	inviteString := invites.BuildInviteString("reverse-token-early", testTargetHost)

	rec := pasteInvite(t, env.pasteRouter(), runID, inviteString)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 (body %s)", rec.Code, rec.Body.String())
	}

	env.requireState(t, runID, validatorcore.StateInviteAccepted)

	if _, err := env.store.GetShareCorrelation(ctx, runID, validatorcore.RoleIncomingInvite, validatorcore.LocalIdentityB); err == nil {
		t.Fatal("correlation row exists after early paste")
	}

	if _, err := env.incoming.GetByTokenForRecipientUserID(ctx, "reverse-token-early", bobID); err == nil {
		t.Fatal("incoming invite stored after early paste")
	}

	if env.poster.calls != 0 {
		t.Fatalf("poster calls = %d, want 0", env.poster.calls)
	}
}

func TestHandleReverseInvite_LaterStatePasteRejected(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		state string
	}{
		{name: "reverse_invite_accepted", state: validatorcore.StateReverseInviteAccepted},
		{name: "forward_share_sent", state: validatorcore.StateForwardShareSent},
		{name: "capability_exercise", state: validatorcore.StateCapabilityExercise},
		{name: "reverse_awaiting_share", state: validatorcore.StateReverseAwaitingShare},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			env := newTestEnv(t)
			ctx := t.Context()
			runID := "run-paste-later-" + tc.name

			env.seedRun(t, runID, tc.state)
			bobID := env.bindBob(t, runID)

			inviteString := invites.BuildInviteString("reverse-token-later", testTargetHost)

			rec := pasteInvite(t, env.pasteRouter(), runID, inviteString)
			if rec.Code != http.StatusConflict {
				t.Fatalf("status = %d, want 409 (body %s)", rec.Code, rec.Body.String())
			}

			env.requireState(t, runID, tc.state)

			if _, err := env.store.GetShareCorrelation(ctx, runID, validatorcore.RoleIncomingInvite, validatorcore.LocalIdentityB); err == nil {
				t.Fatal("correlation row exists after later-state paste")
			}

			if _, err := env.incoming.GetByTokenForRecipientUserID(ctx, "reverse-token-later", bobID); err == nil {
				t.Fatal("incoming invite stored after later-state paste")
			}

			if env.poster.calls != 0 {
				t.Fatalf("poster calls = %d, want 0", env.poster.calls)
			}
		})
	}
}

func TestHandleReverseInvite_UnknownSession(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)

	rec := pasteInvite(t, env.pasteRouter(), "run-missing", invites.BuildInviteString("t", testTargetHost))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestHandleReverseInvite_RejectsInvalidInviteString(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	runID := "run-paste-invalid"

	env.seedRun(t, runID, validatorcore.StateInviteAccepted)
	env.bindBob(t, runID)

	rec := pasteInvite(t, env.pasteRouter(), runID, "not-base64!!!")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}

	env.requireState(t, runID, validatorcore.StateInviteAccepted)
}
