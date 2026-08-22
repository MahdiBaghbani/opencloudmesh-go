// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package reverseinvite_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/address"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
	invitesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/outgoing/accepted"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

// inviteAcceptedEndpoint returns the real product invite-accepted handler
// wrapped in the validator decorator, wired on the test repos.
func (e *testEnv) inviteAcceptedEndpoint() http.HandlerFunc {
	product := accepted.NewHandler(e.outgoing, e.parties, nil, testLocalDomain, "https")

	return e.svc.DecorateInviteAccepted(product.HandleInviteAccepted)
}

func postInviteAccepted(t *testing.T, handler http.HandlerFunc, token, recipientProvider string) *httptest.ResponseRecorder {
	t.Helper()

	return postInviteAcceptedAs(t, handler, token, recipientProvider, "accepter-user")
}

func postInviteAcceptedAs(
	t *testing.T,
	handler http.HandlerFunc,
	token, recipientProvider, userID string,
) *httptest.ResponseRecorder {
	t.Helper()

	body := fmt.Sprintf(
		`{"recipientProvider":%s,"token":%s,"userID":%s,"email":"a@example","name":"Accepter"}`,
		strconv.Quote(recipientProvider),
		strconv.Quote(token),
		strconv.Quote(userID),
	)

	req := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		"/ocm/invite-accepted",
		strings.NewReader(body),
	)
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	handler(rec, req)

	return rec
}

func (e *testEnv) requireWrongAccepterHalt(t *testing.T, runID string) {
	t.Helper()

	run, err := e.store.GetTestRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if run.IsActive {
		t.Fatal("is_active = 1, want 0")
	}

	if run.State != validatorcore.StateTerminalFail {
		t.Fatalf("state = %q, want %q", run.State, validatorcore.StateTerminalFail)
	}

	if run.TerminalReason == nil || *run.TerminalReason != validatorcore.ReasonWrongAccepter {
		t.Fatalf("terminal_reason = %v, want %q", run.TerminalReason, validatorcore.ReasonWrongAccepter)
	}

	if run.DesignatedShareWith != nil {
		t.Fatalf("designated_share_with = %v, want nil after identity halt", run.DesignatedShareWith)
	}
}

func (e *testEnv) unenforceableAccepterEvidence(t *testing.T, runID string) []validatorcore.EvidenceRow {
	t.Helper()

	var rows []validatorcore.EvidenceRow
	if err := e.store.DB().WithContext(t.Context()).
		Where("test_run_id = ? AND area = ? AND step = ? AND reason_code = ?",
			runID,
			validatorcore.SpecificationAreaSharing,
			"invite_accepted",
			"accepter_user_unenforceable",
		).
		Find(&rows).Error; err != nil {
		t.Fatalf("list unenforceable-accepter evidence: %v", err)
	}

	return rows
}

func (e *testEnv) markInviteAccepted(t *testing.T, inviteID, userID, normalizedHost string) {
	t.Helper()

	err := e.outgoing.UpdateStatus(t.Context(), inviteID, invites.InviteStatusAccepted, &invitesoutgoing.Acceptance{
		ProviderFQDN:           normalizedHost,
		UserID:                 userID,
		ProviderFQDNNormalized: normalizedHost,
	})
	if err != nil {
		t.Fatalf("mark invite accepted: %v", err)
	}
}

func TestDecorator_AdvancesOnExactMatch200(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	runID := "run-dec-200"

	env.seedRun(t, runID, validatorcore.StateActiveRunning)

	invite, err := env.svc.MintOutgoingInvite(t.Context(), runID)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	rec := postInviteAccepted(t, env.inviteAcceptedEndpoint(), invite.Token, testTargetHost)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	run, err := env.store.GetTestRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if run.State != validatorcore.StateInviteAccepted {
		t.Fatalf("state = %q, want %q", run.State, validatorcore.StateInviteAccepted)
	}

	if run.DesignatedShareWith == nil || *run.DesignatedShareWith != "accepter-user" {
		t.Fatalf("designated_share_with = %v, want accepter-user", run.DesignatedShareWith)
	}

	requireInboundInviteAcceptedSibling(t, env, runID)
}

func TestDecorator_AdvancesOnConflictWithIdentity(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	runID := "run-dec-409"

	env.seedRun(t, runID, validatorcore.StateActiveRunning)

	invite, err := env.svc.MintOutgoingInvite(t.Context(), runID)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	// The product side already persisted the acceptance (crash before the
	// validator observed it), so the protocol answer is a 409 with identity.
	env.markInviteAccepted(t, invite.ID, "accepter-user", testTargetHost)

	rec := postInviteAccepted(t, env.inviteAcceptedEndpoint(), invite.Token, testTargetHost)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}

	run, err := env.store.GetTestRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if run.State != validatorcore.StateInviteAccepted {
		t.Fatalf("state = %q, want %q", run.State, validatorcore.StateInviteAccepted)
	}

	if run.DesignatedShareWith == nil || *run.DesignatedShareWith != "accepter-user" {
		t.Fatalf("designated_share_with = %v, want accepter-user", run.DesignatedShareWith)
	}

	requireInboundInviteAcceptedSibling(t, env, runID)
}

func TestDecorator_IgnoresConflictWithoutIdentity(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	runID := "run-dec-409-plain"

	env.seedRun(t, runID, validatorcore.StateActiveRunning)

	invite, err := env.svc.MintOutgoingInvite(t.Context(), runID)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	env.markInviteAccepted(t, invite.ID, "accepter-user", testTargetHost)

	// Without the inviting party the product handler answers a plain 409
	// message, which carries no decodable identity.
	if err := env.parties.Delete(t.Context(), runID); err != nil {
		t.Fatalf("delete party A: %v", err)
	}

	rec := postInviteAccepted(t, env.inviteAcceptedEndpoint(), invite.Token, testTargetHost)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}

	env.requireState(t, runID, validatorcore.StateInviteMinted)
}

func TestDecorator_SkipsUncorrelatedInvite(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	ctx := t.Context()
	runID := "run-dec-uncorrelated"

	env.seedRun(t, runID, validatorcore.StateActiveRunning)

	if _, err := env.svc.MintOutgoingInvite(ctx, runID); err != nil {
		t.Fatalf("mint: %v", err)
	}

	// A second invite created by the same run party but never bound to the
	// run's correlation slot must not advance the run.
	other := &invitesoutgoing.OutgoingInvite{
		Token:           "uncorrelated-token",
		ProviderFQDN:    testLocalDomain,
		CreatedByUserID: runID,
		CreatedAt:       time.Now(),
		ExpiresAt:       time.Now().Add(time.Hour),
		Status:          invites.InviteStatusPending,
	}
	if err := env.outgoing.Create(ctx, other); err != nil {
		t.Fatalf("create other invite: %v", err)
	}

	rec := postInviteAccepted(t, env.inviteAcceptedEndpoint(), other.Token, testTargetHost)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (protocol unaffected)", rec.Code)
	}

	env.requireState(t, runID, validatorcore.StateInviteMinted)
}

func TestDecorator_SkipsForeignCreator(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	ctx := t.Context()
	runID := "run-dec-foreign"

	env.seedRun(t, runID, validatorcore.StateActiveRunning)

	invite, err := env.svc.MintOutgoingInvite(ctx, runID)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	// Re-point the invite at a different creator; the decorator must refuse
	// even though the correlation slot matches.
	foreign := &identity.User{
		ID:          "foreign-user",
		Username:    "foreign-user",
		DisplayName: "Foreign",
		Role:        identity.RoleProbe,
		Realm:       testLocalDomain,
		CreatedAt:   time.Now(),
	}
	if err := env.parties.Create(ctx, foreign); err != nil {
		t.Fatalf("create foreign party: %v", err)
	}

	if err := env.store.DB().WithContext(ctx).Exec(
		"UPDATE outgoing_invites SET created_by_user_id = ? WHERE id = ?", foreign.ID, invite.ID,
	).Error; err != nil {
		t.Fatalf("re-point creator: %v", err)
	}

	rec := postInviteAccepted(t, env.inviteAcceptedEndpoint(), invite.Token, testTargetHost)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (protocol unaffected)", rec.Code)
	}

	env.requireState(t, runID, validatorcore.StateInviteMinted)
}

func TestDecorator_WrongAcceptedHostHaltsWrongAccepter(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	runID := "run-dec-wrong-host"

	env.seedRun(t, runID, validatorcore.StateActiveRunning)

	invite, err := env.svc.MintOutgoingInvite(t.Context(), runID)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	rec := postInviteAccepted(t, env.inviteAcceptedEndpoint(), invite.Token, "other-host.example")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (protocol unaffected)", rec.Code)
	}

	env.requireWrongAccepterHalt(t, runID)
}

func TestDecorator_NoActiveRunKeepsProtocolResponse(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	ctx := t.Context()

	// No active run at all; the invite belongs to an ordinary local user.
	creator := &identity.User{
		ID:          "plain-user",
		Username:    "plain-user",
		DisplayName: "Plain",
		CreatedAt:   time.Now(),
	}
	if err := env.parties.Create(ctx, creator); err != nil {
		t.Fatalf("create creator: %v", err)
	}

	invite := &invitesoutgoing.OutgoingInvite{
		Token:           "plain-token",
		ProviderFQDN:    testLocalDomain,
		CreatedByUserID: creator.ID,
		CreatedAt:       time.Now(),
		ExpiresAt:       time.Now().Add(time.Hour),
		Status:          invites.InviteStatusPending,
	}
	if err := env.outgoing.Create(ctx, invite); err != nil {
		t.Fatalf("create invite: %v", err)
	}

	rec := postInviteAccepted(t, env.inviteAcceptedEndpoint(), invite.Token, testTargetHost)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	if !strings.Contains(rec.Body.String(), "userID") {
		t.Fatalf("response body = %q, want identity payload", rec.Body.String())
	}
}

func TestDecorator_RejectsOversizedRequestBody(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)

	called := false

	handler := env.svc.DecorateInviteAccepted(func(w http.ResponseWriter, _ *http.Request) {
		called = true

		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(
		t.Context(), http.MethodPost, "/ocm/invite-accepted",
		strings.NewReader(strings.Repeat("x", (64<<10)+1)),
	)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if called {
		t.Fatal("product handler called for an oversized body")
	}

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}
}

func TestDecorator_BodyAtCapPassesThrough(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)

	called := false

	handler := env.svc.DecorateInviteAccepted(func(w http.ResponseWriter, r *http.Request) {
		called = true

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read restored body: %v", err)
		}

		if len(body) != 64<<10 {
			t.Errorf("restored body = %d bytes, want %d", len(body), 64<<10)
		}

		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(
		t.Context(), http.MethodPost, "/ocm/invite-accepted",
		strings.NewReader(strings.Repeat("x", 64<<10)),
	)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if !called {
		t.Fatal("product handler not called for a body at the cap")
	}

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestDecorator_PlainUserMismatchHaltsWrongAccepter(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	runID := "run-dec-plain-mismatch"

	env.seedRunAt(t, runID, validatorcore.StateActiveRunning, "o.com", new("malek@o.com"))

	invite, err := env.svc.MintOutgoingInvite(t.Context(), runID)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	rec := postInviteAcceptedAs(t, env.inviteAcceptedEndpoint(), invite.Token, "o.com", "omar")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (protocol unaffected)", rec.Code)
	}

	env.requireWrongAccepterHalt(t, runID)
}

func TestDecorator_OpaqueUserMismatchWarnsAndAdvances(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	runID := "run-dec-opaque-warn"
	opaqueUser := address.EncodeFederatedOpaqueID("omar", "o.com")

	env.seedRunAt(t, runID, validatorcore.StateActiveRunning, "o.com", new("malek@o.com"))

	invite, err := env.svc.MintOutgoingInvite(t.Context(), runID)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	rec := postInviteAcceptedAs(t, env.inviteAcceptedEndpoint(), invite.Token, "o.com", opaqueUser)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	run, err := env.store.GetTestRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if run.State != validatorcore.StateInviteAccepted {
		t.Fatalf("state = %q, want %q", run.State, validatorcore.StateInviteAccepted)
	}

	if run.DesignatedShareWith == nil || *run.DesignatedShareWith != opaqueUser {
		t.Fatalf("designated_share_with = %v, want wire opaque id", run.DesignatedShareWith)
	}

	rows := env.unenforceableAccepterEvidence(t, runID)
	if len(rows) != 1 {
		t.Fatalf("unenforceable evidence = %d, want 1", len(rows))
	}

	if rows[0].Severity != validatorcore.GradeWarn {
		t.Fatalf("severity = %q, want %q", rows[0].Severity, validatorcore.GradeWarn)
	}

	requireInboundInviteAcceptedSibling(t, env, runID)
}

func TestDecorator_BareURLStartEnforcesHostOnly(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	runID := "run-dec-bare-url"

	env.seedRun(t, runID, validatorcore.StateActiveRunning)

	invite, err := env.svc.MintOutgoingInvite(t.Context(), runID)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	rec := postInviteAcceptedAs(t, env.inviteAcceptedEndpoint(), invite.Token, testTargetHost, "omar")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	run, err := env.store.GetTestRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if run.State != validatorcore.StateInviteAccepted {
		t.Fatalf("state = %q, want %q", run.State, validatorcore.StateInviteAccepted)
	}

	if run.DesignatedShareWith == nil || *run.DesignatedShareWith != "omar" {
		t.Fatalf("designated_share_with = %v, want omar", run.DesignatedShareWith)
	}

	if len(env.unenforceableAccepterEvidence(t, runID)) != 0 {
		t.Fatal("bare URL start must not write unenforceable-user evidence")
	}
}

func TestDecorator_ConflictReplayDoesNotOverwritePin(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	runID := "run-dec-replay-pin"

	env.seedRunAt(t, runID, validatorcore.StateActiveRunning, testTargetHost, new("malek@"+testTargetHost))

	invite, err := env.svc.MintOutgoingInvite(t.Context(), runID)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	first := postInviteAcceptedAs(t, env.inviteAcceptedEndpoint(), invite.Token, testTargetHost, "malek")
	if first.Code != http.StatusOK {
		t.Fatalf("first status = %d, want 200", first.Code)
	}

	replay := postInviteAcceptedAs(t, env.inviteAcceptedEndpoint(), invite.Token, testTargetHost, "omar")
	if replay.Code != http.StatusConflict {
		t.Fatalf("replay status = %d, want 409", replay.Code)
	}

	run, err := env.store.GetTestRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if run.State != validatorcore.StateInviteAccepted {
		t.Fatalf("state = %q, want %q", run.State, validatorcore.StateInviteAccepted)
	}

	if run.DesignatedShareWith == nil || *run.DesignatedShareWith != "malek" {
		t.Fatalf("designated_share_with = %v, want malek", run.DesignatedShareWith)
	}
}

func TestDecorator_ConflictReplayDoesNotMoveCapabilityExercise(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	runID := "run-dec-replay-exercise"

	env.seedRunAt(t, runID, validatorcore.StateActiveRunning, testTargetHost, new("malek@"+testTargetHost))

	invite, err := env.svc.MintOutgoingInvite(t.Context(), runID)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	first := postInviteAcceptedAs(t, env.inviteAcceptedEndpoint(), invite.Token, testTargetHost, "malek")
	if first.Code != http.StatusOK {
		t.Fatalf("first status = %d, want 200", first.Code)
	}

	if updateErr := env.store.DB().WithContext(t.Context()).
		Model(&validatorcore.TestRun{}).
		Where("test_run_id = ?", runID).
		Update("state", validatorcore.StateCapabilityExercise).Error; updateErr != nil {
		t.Fatalf("force capability_exercise: %v", updateErr)
	}

	replay := postInviteAcceptedAs(t, env.inviteAcceptedEndpoint(), invite.Token, testTargetHost, "omar")
	if replay.Code != http.StatusConflict {
		t.Fatalf("replay status = %d, want 409", replay.Code)
	}

	run, err := env.store.GetTestRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if !run.IsActive {
		t.Fatal("is_active = 0, replay must not release the run")
	}

	if run.State != validatorcore.StateCapabilityExercise {
		t.Fatalf("state = %q, want %q", run.State, validatorcore.StateCapabilityExercise)
	}

	if run.DesignatedShareWith == nil || *run.DesignatedShareWith != "malek" {
		t.Fatalf("designated_share_with = %v, want malek", run.DesignatedShareWith)
	}

	if run.TerminalReason != nil {
		t.Fatalf("terminal_reason = %v, want nil", run.TerminalReason)
	}
}
