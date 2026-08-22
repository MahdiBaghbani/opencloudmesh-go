// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package forwardshare_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/passive"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/address"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
	sharesincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/incoming"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

// runStatsParitySessions drives three sequential opted-in sessions against
// the same receiver host: a timely pass, a hard fail carrying a sharing
// failure, and a timeout interruption healed by the late reverse share.
func runStatsParitySessions(t *testing.T, env *courierMatrixEnv) ([]string, map[string]string) {
	t.Helper()

	run1 := env.startActiveSession(t)
	env.acceptForwardInvite(t, run1)
	env.pasteReverseInvite(t, run1)
	env.dispatchForwardShare(t, run1)
	env.exerciseForwardCapability(t, run1)
	providerID1 := env.deliverReverseShare(t, run1, "reverse_share_observed")

	run2 := env.startActiveSession(t)
	env.acceptForwardInvite(t, run2)
	env.pasteReverseInvite(t, run2)
	applySharingFailure(t, env, run2)

	if err := env.store.ReleaseActiveHardFail(t.Context(), run2, validatorcore.ReasonActiveHardFailCorrelation); err != nil {
		t.Fatalf("release hard fail: %v", err)
	}

	run3 := env.startActiveSession(t)
	env.acceptForwardInvite(t, run3)
	env.pasteReverseInvite(t, run3)
	env.dispatchForwardShare(t, run3)
	env.exerciseForwardCapability(t, run3)
	releaseInterruptedOnTimeout(t, env, run3)
	providerID3 := env.deliverReverseShare(t, run3, validatorcore.ReasonLateReverseShare)

	return []string{run1, run2, run3}, map[string]string{run1: providerID1, run3: providerID3}
}

// applySharingFailure records a grade-affecting sharing failure for the run.
func applySharingFailure(t *testing.T, env *courierMatrixEnv, runID string) {
	t.Helper()

	if err := env.store.ApplyEvidenceFact(t.Context(), validatorcore.ApplyEvidenceFactInput{
		TestRunID:    runID,
		Area:         "sharing",
		Step:         "reverse_share",
		ReasonCode:   "reverse_share_failed",
		Severity:     validatorcore.GradeFail,
		AffectsGrade: true,
		Leg:          "reverse",
	}); err != nil {
		t.Fatalf("apply sharing failure: %v", err)
	}
}

// releaseInterruptedOnTimeout terminalizes the waiting run as interrupted on
// the reverse-share timeout and proves the interrupted world.
func releaseInterruptedOnTimeout(t *testing.T, env *courierMatrixEnv, runID string) {
	t.Helper()

	if err := env.store.ReleaseActiveTerminalFrom(
		t.Context(),
		runID,
		[]string{validatorcore.StateReverseAwaitingShare},
		validatorcore.ActiveTerminalUpdate{
			State:          validatorcore.StateInterrupted,
			TerminalReason: validatorcore.ReasonReverseShareTimeout,
		},
	); err != nil {
		t.Fatalf("release interrupted: %v", err)
	}

	run := env.requireRun(t, runID)

	if run.State != validatorcore.StateInterrupted {
		t.Fatalf("state = %q, want %q", run.State, validatorcore.StateInterrupted)
	}

	if run.TerminalReason == nil || *run.TerminalReason != validatorcore.ReasonReverseShareTimeout {
		t.Fatalf("terminal_reason = %v, want %q", run.TerminalReason, validatorcore.ReasonReverseShareTimeout)
	}
}

// observeDuplicateShare re-delivers an already-observed reverse share.
func observeDuplicateShare(t *testing.T, env *courierMatrixEnv, run *validatorcore.TestRun, providerID string) {
	t.Helper()

	duplicate := &sharesincoming.IncomingShare{
		ShareID:         matrixShareID(t),
		ProviderID:      providerID,
		SenderHost:      env.targetHost,
		RecipientUserID: *run.BobUserID,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}

	if err := env.reverseShare.ObserveCreatedShare(t.Context(), duplicate); err != nil {
		t.Fatalf("observe duplicate share: %v", err)
	}
}

// retryTerminalStats re-drives the terminal statistics write for the run.
func retryTerminalStats(t *testing.T, env *courierMatrixEnv, runID string) {
	t.Helper()

	if err := env.store.RetryTerminalStats(t.Context(), runID); err != nil {
		t.Fatalf("RetryTerminalStats(%s): %v", runID, err)
	}
}

// requireNoTerminalFootprint proves the run carries no terminal timestamp and
// no statistics rows yet.
func requireNoTerminalFootprint(t *testing.T, env *courierMatrixEnv, runID string) {
	t.Helper()

	run := env.requireRun(t, runID)

	if run.FinishedAt != nil {
		t.Fatalf("finished_at = %v, want nil", run.FinishedAt)
	}

	if got := env.countStatsRaw(t); got != 0 {
		t.Fatalf("stats_raw rows = %d, want 0", got)
	}
}

// requirePassEvidenceTuple proves the pass path recorded the reverse-invite
// accept, outgoing invite-accepted, forward-share send, reverse-share receipt,
// token exchange, and capability exercise facts.
func requirePassEvidenceTuple(t *testing.T, env *courierMatrixEnv, runID string) {
	t.Helper()

	if got := len(env.evidenceRows(t, runID, validatorcore.SpecificationAreaSharing, "invite_accepted", "reverse_invite_accepted")); got != 1 {
		t.Fatalf("reverse-invite evidence = %d, want 1", got)
	}

	if got := len(env.evidenceRows(t, runID, "capability", "file_opened", "token_exchange")); got != 1 {
		t.Fatalf("capability evidence = %d, want 1", got)
	}

	if got := len(env.evidenceRows(t, runID, "sharing", "reverse_share", "reverse_share_received")); got != 1 {
		t.Fatalf("reverse-share evidence = %d, want 1", got)
	}

	if got := len(env.evidenceRows(t, runID, validatorcore.SpecificationAreaSharing, "share_sent", "forward_share_sent")); got != 1 {
		t.Fatalf("forward-share evidence = %d, want 1", got)
	}

	if got := len(env.evidenceRows(t, runID, validatorcore.SpecificationAreaSharing, "invite_accepted", "outgoing_invite_accepted")); got != 1 {
		t.Fatalf("outgoing invite-accepted evidence = %d, want 1", got)
	}

	if got := len(env.evidenceRows(t, runID, validatorcore.SpecificationAreaToken, "exchange", "token_exchanged")); got != 1 {
		t.Fatalf("token evidence = %d, want 1", got)
	}

	if got := env.countEvidence(t, runID); got != 6 {
		t.Fatalf("evidence rows = %d, want 6", got)
	}
}

// requireRaterOutcome loads the specification rating and proves the state,
// terminal flag, and overall grade. An empty wantGrade requires a nil grade.
func requireRaterOutcome(
	t *testing.T,
	env *courierMatrixEnv,
	run *validatorcore.TestRun,
	wantState, wantGrade string,
) validatorcore.SpecificationScore {
	t.Helper()

	score, _, err := env.store.LoadSpecificationRating(t.Context(), run)
	if err != nil {
		t.Fatalf("LoadSpecificationRating: %v", err)
	}

	if score.State != wantState {
		t.Fatalf("rater state = %q, want %q", score.State, wantState)
	}

	if !score.Terminal {
		t.Fatal("rater terminal = false, want true")
	}

	if wantGrade == "" && score.Grade != nil {
		t.Fatalf("rater grade = %q, want nil", *score.Grade)
	}

	if wantGrade != "" && (score.Grade == nil || *score.Grade != wantGrade) {
		t.Fatalf("rater grade = %v, want %q", score.Grade, wantGrade)
	}

	return score
}

// assertOutboundAcceptance proves the captured outbound invite-accepted post
// targeted the peer host and carried the pasted token for the bound Bob.
func assertOutboundAcceptance(t *testing.T, env *courierMatrixEnv, token, bobID string) {
	t.Helper()

	if env.poster.lastHost != env.targetHost {
		t.Fatalf("outbound acceptance host = %q, want %q", env.poster.lastHost, env.targetHost)
	}

	var payload spec.InviteAcceptedRequest

	if err := json.Unmarshal(env.poster.lastBody, &payload); err != nil {
		t.Fatalf("decode outbound acceptance body: %v", err)
	}

	if payload.Token != token {
		t.Fatalf("outbound acceptance token = %q, want %q", payload.Token, token)
	}

	wantUserID := address.EncodeFederatedOpaqueID(bobID, testLocalDomain)

	if payload.UserID != wantUserID {
		t.Fatalf("outbound acceptance user id = %q, want %q", payload.UserID, wantUserID)
	}
}

// assertInSessionIdentityReuse repeats the mint, solicitation, paste, and
// acceptance callback inside one session and proves the bound identities are
// reused rather than rotated.
func assertInSessionIdentityReuse(t *testing.T, env *courierMatrixEnv, runID, outToken, reverseToken string) {
	t.Helper()

	again, err := env.reverseInvite.MintOutgoingInvite(t.Context(), runID)
	if err != nil {
		t.Fatalf("re-mint outgoing invite: %v", err)
	}

	if again.Token != outToken {
		t.Fatalf("re-minted token = %q, want reused %q", again.Token, outToken)
	}

	if solicitErr := env.reverseInvite.SolicitReverse(t.Context(), runID); solicitErr != nil {
		t.Fatalf("re-solicit reverse: %v", solicitErr)
	}

	posterCalls := env.poster.calls

	env.postReverseInvite(t, runID, invites.BuildInviteString(reverseToken, env.targetHost))

	if env.poster.calls != posterCalls {
		t.Fatalf("poster calls = %d, want unchanged %d", env.poster.calls, posterCalls)
	}

	env.requireState(t, runID, validatorcore.StateReverseInviteAccepted)

	rec := env.postInviteAcceptedRaw(t, outToken)

	if rec.Code != http.StatusConflict {
		t.Fatalf("repeat invite-accepted status = %d, want 409: %s", rec.Code, rec.Body.String())
	}

	run := env.requireRun(t, runID)

	if run.DesignatedShareWith == nil || *run.DesignatedShareWith != matrixRemoteUser {
		t.Fatalf("designated_share_with = %v, want %q", run.DesignatedShareWith, matrixRemoteUser)
	}
}

// collectSensitiveMarkers proves the ephemeral party shape for both sessions
// and returns every identity marker that public serialization must not carry.
func collectSensitiveMarkers(
	t *testing.T,
	env *courierMatrixEnv,
	run1, run2, outToken1, outToken2, token1, token2, providerID1, providerID2 string,
) []string {
	t.Helper()

	run1Final := env.requireRun(t, run1)
	run2Final := env.requireRun(t, run2)

	alice1 := requireParty(t, env, run1)
	alice2 := requireParty(t, env, run2)
	bob1 := requireParty(t, env, *run1Final.BobUserID)
	bob2 := requireParty(t, env, *run2Final.BobUserID)

	requireUUIDv7(t, alice1.ID)
	requireUUIDv7(t, alice2.ID)
	requireUUIDv7(t, bob1.ID)
	requireUUIDv7(t, bob2.ID)

	if bob1.ID == run1 || bob2.ID == run2 {
		t.Fatal("bob party id must differ from the session's test run id")
	}

	ids := map[string]bool{alice1.ID: true, alice2.ID: true, bob1.ID: true, bob2.ID: true}

	if len(ids) != 4 {
		t.Fatalf("distinct party ids across sessions = %d, want 4", len(ids))
	}

	for _, party := range []*identity.User{alice1, alice2, bob1, bob2} {
		requireProbePartyShape(t, party)
	}

	return []string{
		run1, run2,
		*run1Final.BobUserID, *run2Final.BobUserID,
		// Federated-opaque wire forms of the Bob ids, so an encoded-only
		// leak is caught as well.
		address.EncodeFederatedOpaqueID(*run1Final.BobUserID, testLocalDomain),
		address.EncodeFederatedOpaqueID(*run2Final.BobUserID, testLocalDomain),
		outToken1, outToken2, token1, token2,
		matrixRemoteUser,
		providerID1, providerID2,
		bob1.Email, bob2.Email,
		env.requireReservation(t, run1).SharedSecret,
		env.requireReservation(t, run2).SharedSecret,
	}
}

// collectPublicBlobs serializes the anonymous polls, the public statistics
// endpoint payload, and the specification evidence for both sessions.
func collectPublicBlobs(t *testing.T, env *courierMatrixEnv, run1, run2 string) []string {
	t.Helper()

	passiveHandler := passive.NewHandler(env.store, nil)

	router := chi.NewRouter()
	router.Method(http.MethodGet, passive.RouteAPISession, http.HandlerFunc(passiveHandler.HandleSession))
	router.Method(http.MethodGet, passive.RouteAPIStatistics, http.HandlerFunc(passiveHandler.HandleStatistics))

	blobs := make([]string, 0, 5)

	for _, id := range []string{run1, run2} {
		blobs = append(blobs, getFromRouter(t, router, "/api/session/"+id))
	}

	blobs = append(blobs, getFromRouter(t, router, "/api/statistics?days=0"))

	for _, id := range []string{run1, run2} {
		run := env.requireRun(t, id)

		score, items, err := env.store.LoadSpecificationRating(t.Context(), run)
		if err != nil {
			t.Fatalf("LoadSpecificationRating(%s): %v", id, err)
		}

		blobs = append(blobs, string(mustJSON(t, struct {
			Score    validatorcore.SpecificationScore      `json:"score"`
			Evidence []validatorcore.SpecificationEvidence `json:"evidence"`
		}{score, items})))
	}

	return blobs
}

// getFromRouter serves one GET through the router and requires a 200 body.
func getFromRouter(t *testing.T, router *chi.Mux, path string) string {
	t.Helper()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s status = %d, want 200: %s", path, rec.Code, rec.Body.String())
	}

	return rec.Body.String()
}

// mustJSON marshals a payload that must serialize.
func mustJSON(t *testing.T, payload any) []byte {
	t.Helper()

	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	return body
}
