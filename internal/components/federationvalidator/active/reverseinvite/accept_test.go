// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package reverseinvite_test

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/active/reverseinvite"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
	invitesincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/incoming"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

// seedImportedRun drives the real import path and leaves the run in
// reverse_invite_imported with a pending incoming invite for Bob.
func (e *testEnv) seedImportedRun(t *testing.T, runID string) (bobID, inviteID string) {
	t.Helper()

	const token = "reverse-token-1"

	e.seedRun(t, runID, validatorcore.StateReverseAwaitingInvite)
	bobID = e.bindBob(t, runID)

	invite, err := e.createIncoming(t, invites.BuildInviteString(token, testTargetHost), token, testTargetHost, bobID)
	if err != nil {
		t.Fatalf("create incoming: %v", err)
	}

	if err := e.store.ImportReverseInvite(t.Context(), runID, token, invite.ID); err != nil {
		t.Fatalf("import: %v", err)
	}

	return bobID, invite.ID
}

func TestAcceptIncoming_SendsAsBobAndAdvances(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	runID := "run-accept-happy"

	bobID, inviteID := env.seedImportedRun(t, runID)

	if err := env.svc.AcceptIncoming(t.Context(), runID); err != nil {
		t.Fatalf("accept: %v", err)
	}

	env.requireState(t, runID, validatorcore.StateReverseInviteAccepted)

	if env.poster.calls != 1 {
		t.Fatalf("poster calls = %d, want 1", env.poster.calls)
	}

	if !strings.Contains(string(env.poster.lastBody), "reverse-token-1") {
		t.Fatalf("poster body = %s, want the invite token", env.poster.lastBody)
	}

	invite, err := env.incoming.GetByIDForRecipientUserID(t.Context(), inviteID, bobID)
	if err != nil {
		t.Fatalf("load invite: %v", err)
	}

	if invite.Status != invites.InviteStatusAccepted {
		t.Fatalf("status = %q, want accepted", invite.Status)
	}

	if invite.SenderFQDNNormalized != testTargetHost {
		t.Fatalf("sender normalized = %q, want %q", invite.SenderFQDNNormalized, testTargetHost)
	}

	if got := env.countEvidence(t, runID); got != 1 {
		t.Fatalf("evidence rows = %d, want 1", got)
	}
}

func TestAcceptIncoming_LocallyAcceptedHealsSameInviteID(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	ctx := t.Context()
	runID := "run-accept-heal"

	bobID, inviteID := env.seedImportedRun(t, runID)

	// The invite is already accepted locally (crash between the remote accept
	// and the validator CAS): no wire call, same correlation healed.
	if err := env.incoming.UpdateStatusForRecipientUserID(ctx, inviteID, bobID, invites.InviteStatusAccepted, &invitesincoming.Acceptance{
		UserID:                 "sender@peer.example",
		ProviderFQDN:           testTargetHost,
		ProviderFQDNNormalized: testTargetHost,
	}); err != nil {
		t.Fatalf("pre-accept invite: %v", err)
	}

	if err := env.svc.AcceptIncoming(ctx, runID); err != nil {
		t.Fatalf("accept: %v", err)
	}

	if env.poster.calls != 0 {
		t.Fatalf("poster calls = %d, want 0 for local healing", env.poster.calls)
	}

	env.requireState(t, runID, validatorcore.StateReverseInviteAccepted)

	corr, err := env.store.GetShareCorrelation(ctx, runID, validatorcore.RoleIncomingInvite, validatorcore.LocalIdentityB)
	if err != nil {
		t.Fatalf("GetShareCorrelation: %v", err)
	}

	if corr.InviteID == nil || *corr.InviteID != inviteID {
		t.Fatalf("correlation invite id = %v, want %q", corr.InviteID, inviteID)
	}

	// A second accept is idempotent and never re-writes the evidence tuple.
	if err := env.svc.AcceptIncoming(ctx, runID); err != nil {
		t.Fatalf("accept retry: %v", err)
	}

	if got := env.countEvidence(t, runID); got != 1 {
		t.Fatalf("evidence rows = %d, want 1", got)
	}
}

func TestAcceptIncoming_RemoteConflictPersistsAndHeals(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	ctx := t.Context()
	runID := "run-accept-remote-409"

	bobID, inviteID := env.seedImportedRun(t, runID)

	env.poster.status = http.StatusConflict
	env.poster.body = `{"userID":"sender@peer.example","email":"s@example","name":"Sender"}`

	if err := env.svc.AcceptIncoming(ctx, runID); err != nil {
		t.Fatalf("accept: %v", err)
	}

	env.requireState(t, runID, validatorcore.StateReverseInviteAccepted)

	invite, err := env.incoming.GetByIDForRecipientUserID(ctx, inviteID, bobID)
	if err != nil {
		t.Fatalf("load invite: %v", err)
	}

	if invite.Status != invites.InviteStatusAccepted {
		t.Fatalf("status = %q, want accepted", invite.Status)
	}

	if got := env.countEvidence(t, runID); got != 1 {
		t.Fatalf("evidence rows = %d, want 1", got)
	}
}

func TestAcceptIncoming_RemoteErrorDoesNotAdvance(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	runID := "run-accept-remote-500"

	env.seedImportedRun(t, runID)

	env.poster.status = http.StatusBadGateway
	env.poster.body = `{"message":"down"}`

	if err := env.svc.AcceptIncoming(t.Context(), runID); err == nil {
		t.Fatal("accept succeeded against a failing peer")
	}

	env.requireState(t, runID, validatorcore.StateReverseInviteImported)

	if got := env.countEvidence(t, runID); got != 0 {
		t.Fatalf("evidence rows = %d, want 0", got)
	}
}

func TestAcceptIncoming_RejectsTokenMismatch(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	ctx := t.Context()
	runID := "run-accept-token-mismatch"

	_, _ = env.seedImportedRun(t, runID)

	// Corrupt the run's imported token so run, correlation, and invite
	// disagree; the orchestrator must refuse rather than pick anything.
	if err := env.store.DB().WithContext(ctx).Model(&validatorcore.TestRun{}).
		Where("test_run_id = ?", runID).
		Update("reverse_invite_token", "tampered-token").Error; err != nil {
		t.Fatalf("tamper token: %v", err)
	}

	err := env.svc.AcceptIncoming(ctx, runID)
	if !errors.Is(err, reverseinvite.ErrCorrelationMismatch) {
		t.Fatalf("accept = %v, want ErrCorrelationMismatch", err)
	}

	env.requireState(t, runID, validatorcore.StateReverseInviteImported)

	if env.poster.calls != 0 {
		t.Fatalf("poster calls = %d, want 0", env.poster.calls)
	}
}

func TestAcceptIncoming_RejectsSenderHostMismatch(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	ctx := t.Context()
	runID := "run-accept-host-mismatch"

	_, inviteID := env.seedImportedRun(t, runID)

	// Re-point the imported invite at a sender that is not the session
	// target; the accept must refuse before any outbound traffic.
	if err := env.store.DB().WithContext(ctx).Exec(
		"UPDATE incoming_invites SET sender_fqdn = ? WHERE id = ?", "other-host.example", inviteID,
	).Error; err != nil {
		t.Fatalf("re-point sender: %v", err)
	}

	err := env.svc.AcceptIncoming(ctx, runID)
	if !errors.Is(err, reverseinvite.ErrCorrelationMismatch) {
		t.Fatalf("accept = %v, want ErrCorrelationMismatch", err)
	}

	env.requireState(t, runID, validatorcore.StateReverseInviteImported)

	if env.poster.calls != 0 {
		t.Fatalf("poster calls = %d, want 0", env.poster.calls)
	}

	if got := env.countEvidence(t, runID); got != 0 {
		t.Fatalf("evidence rows = %d, want 0", got)
	}
}

func TestAcceptIncoming_RequiresExactCorrelation(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	runID := "run-accept-no-corr"

	env.seedRun(t, runID, validatorcore.StateReverseInviteImported)
	env.bindBob(t, runID)

	err := env.svc.AcceptIncoming(t.Context(), runID)
	if !errors.Is(err, validatorcore.ErrShareCorrelationNotFound) {
		t.Fatalf("accept = %v, want ErrShareCorrelationNotFound", err)
	}

	if env.poster.calls != 0 {
		t.Fatalf("poster calls = %d, want 0", env.poster.calls)
	}
}
