// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package reverseinvite_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
	invitesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

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
