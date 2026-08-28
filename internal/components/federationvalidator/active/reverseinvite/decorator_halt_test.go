// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package reverseinvite_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/address"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
	invitesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

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
