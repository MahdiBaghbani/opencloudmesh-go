// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package repos_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
	invitesincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/incoming"
	invitesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/repos"
)

// runIncomingInviteRepoContract verifies CRUD, list, recipient-scope enforcement,
// auto-fill, and ErrInviteNotFound sentinel for the IncomingInviteRepo
// interface.
func runIncomingInviteRepoContract(t *testing.T, r *repos.Repos) {
	t.Helper()

	ctx := context.Background()

	t.Run("CRUD", func(t *testing.T) { runIncomingInviteRepoContractCRUD(t, ctx, r) })
	t.Run("ListByRecipientUserID", func(t *testing.T) { runIncomingInviteRepoContractListByRecipientUserID(t, ctx, r) })
	t.Run("EnforcesRecipientScope", func(t *testing.T) { runIncomingInviteRepoContractEnforcesRecipientScope(t, ctx, r) })
	t.Run("AutoFill", func(t *testing.T) { runIncomingInviteRepoContractAutoFill(t, ctx, r) })
	t.Run("IDNotFoundSentinel", func(t *testing.T) { runIncomingInviteRepoContractIDNotFoundSentinel(t, ctx, r) })
}

func runIncomingInviteRepoContractCRUD(t *testing.T, ctx context.Context, r *repos.Repos) {
	t.Helper()

	invite := &invitesincoming.IncomingInvite{
		ID:              "ct-in-inv-1",
		Token:           "ct-in-token-1",
		InviteString:    "b64ct-in",
		SenderFQDN:      "ct.sender.invite.example",
		RecipientUserID: "ct-recipient-1",
		Status:          invites.InviteStatusPending,
		ReceivedAt:      time.Unix(time.Now().Unix(), 0).UTC(),
	}
	if err := r.IncomingInvites.Create(ctx, invite); err != nil {
		t.Fatalf("Create: %v", err)
	}

	assertIncomingInviteReadPaths(t, ctx, r, invite)
	acceptIncomingInvite(t, ctx, r, invite)
	assertIncomingAcceptedState(t, ctx, r, invite)
	assertIncomingAcceptedScopeMisses(t, ctx, r, invite.RecipientUserID)
	assertIncomingCreateRejectedAcceptedWithoutIdentity(t, ctx, r)
	assertIncomingUpdateRejectedWithoutIdentity(t, ctx, r)
	assertIncomingInviteDelete(t, ctx, r, invite)
}

// assertIncomingInviteReadPaths checks the ID and token read paths return the
// created invite.
func assertIncomingInviteReadPaths(t *testing.T, ctx context.Context, r *repos.Repos, invite *invitesincoming.IncomingInvite) {
	t.Helper()

	got, err := r.IncomingInvites.GetByIDForRecipientUserID(ctx, invite.ID, invite.RecipientUserID)
	if err != nil {
		t.Fatalf("GetByIDForRecipientUserID: %v", err)
	}

	if got.Token != invite.Token {
		t.Errorf("Token: got %q, want %q", got.Token, invite.Token)
	}

	got, err = r.IncomingInvites.GetByTokenForRecipientUserID(ctx, invite.Token, invite.RecipientUserID)
	if err != nil {
		t.Fatalf("GetByTokenForRecipientUserID: %v", err)
	}

	if got.ID != invite.ID {
		t.Errorf("ID: got %q, want %q", got.ID, invite.ID)
	}
}

// acceptIncomingInvite marks the invite accepted with sender identity.
func acceptIncomingInvite(t *testing.T, ctx context.Context, r *repos.Repos, invite *invitesincoming.IncomingInvite) {
	t.Helper()

	if err := r.IncomingInvites.UpdateStatusForRecipientUserID(
		ctx, invite.ID, invite.RecipientUserID, invites.InviteStatusAccepted, &invitesincoming.Acceptance{
			UserID:                 "ct-sender-user-1",
			ProviderFQDNNormalized: "ct.sender.invite.example",
		},
	); err != nil {
		t.Fatalf("UpdateStatusForRecipientUserID: %v", err)
	}
}

// assertIncomingAcceptedState checks post-accept persisted state and the
// accepted-sender lookup.
func assertIncomingAcceptedState(t *testing.T, ctx context.Context, r *repos.Repos, invite *invitesincoming.IncomingInvite) {
	t.Helper()

	got, err := r.IncomingInvites.GetByIDForRecipientUserID(ctx, invite.ID, invite.RecipientUserID)
	if err != nil {
		t.Fatalf("GetByIDForRecipientUserID after update: %v", err)
	}

	if got.Status != invites.InviteStatusAccepted {
		t.Errorf("Status after update: got %q, want accepted", got.Status)
	}

	if got.SenderUserID != "ct-sender-user-1" {
		t.Errorf("SenderUserID after update: got %q, want ct-sender-user-1", got.SenderUserID)
	}

	if got.SenderFQDNNormalized != "ct.sender.invite.example" {
		t.Errorf("SenderFQDNNormalized after update: got %q, want ct.sender.invite.example", got.SenderFQDNNormalized)
	}

	found, err := r.IncomingInvites.FindAcceptedForSender(ctx, invite.RecipientUserID, "ct-sender-user-1", "ct.sender.invite.example")
	if err != nil {
		t.Fatalf("FindAcceptedForSender: %v", err)
	}

	if found.ID != invite.ID {
		t.Errorf("FindAcceptedForSender ID: got %q, want %q", found.ID, invite.ID)
	}
}

// assertIncomingAcceptedScopeMisses checks wrong host, user, or recipient
// queries never match the accepted invite.
func assertIncomingAcceptedScopeMisses(t *testing.T, ctx context.Context, r *repos.Repos, recipientUserID string) {
	t.Helper()

	cases := []struct {
		name       string
		recipient  string
		senderUser string
		senderFQDN string
	}{
		{"wrong host", recipientUserID, "ct-sender-user-1", "other.example"},
		{"wrong user", recipientUserID, "ct-other-user", "ct.sender.invite.example"},
		{"wrong recipient", "ct-wrong-recipient", "ct-sender-user-1", "ct.sender.invite.example"},
	}

	for _, tc := range cases {
		if _, err := r.IncomingInvites.FindAcceptedForSender(
			ctx, tc.recipient, tc.senderUser, tc.senderFQDN,
		); !errors.Is(err, invites.ErrInviteNotFound) {
			t.Errorf("FindAcceptedForSender %s: expected ErrInviteNotFound, got %v", tc.name, err)
		}
	}
}

// assertIncomingCreateRejectedAcceptedWithoutIdentity checks that creating an
// incoming invite directly in accepted status without sender identity is
// rejected with ErrInvalidCreateStatus across every backend.
func assertIncomingCreateRejectedAcceptedWithoutIdentity(t *testing.T, ctx context.Context, r *repos.Repos) {
	t.Helper()

	invite := &invitesincoming.IncomingInvite{
		ID:              "ct-in-inv-create-accepted",
		Token:           "ct-in-token-create-accepted",
		InviteString:    "b64ct-in-create-accepted",
		SenderFQDN:      "ct.create-accepted.example",
		RecipientUserID: "ct-recipient-create-accepted",
		Status:          invites.InviteStatusAccepted,
		ReceivedAt:      time.Unix(time.Now().Unix(), 0).UTC(),
	}
	if err := r.IncomingInvites.Create(ctx, invite); !errors.Is(err, invites.ErrInvalidCreateStatus) {
		t.Errorf("Create accepted without identity: expected ErrInvalidCreateStatus, got %v", err)
	}
}

// assertIncomingUpdateRejectedWithoutIdentity checks an accepted update
// carrying no sender identity is rejected with ErrInvalidAcceptedIdentity and
// that the stored row is left untouched (no partial write leaks through).
func assertIncomingUpdateRejectedWithoutIdentity(t *testing.T, ctx context.Context, r *repos.Repos) {
	t.Helper()

	noIdentity := &invitesincoming.IncomingInvite{
		ID:              "ct-in-inv-noident",
		Token:           "ct-in-token-noident",
		InviteString:    "b64ct-in-noident",
		SenderFQDN:      "ct.noident.invite.example",
		RecipientUserID: "ct-recipient-noident",
		Status:          invites.InviteStatusPending,
		ReceivedAt:      time.Unix(time.Now().Unix(), 0).UTC(),
	}
	if err := r.IncomingInvites.Create(ctx, noIdentity); err != nil {
		t.Fatalf("Create noIdentity: %v", err)
	}

	if err := r.IncomingInvites.UpdateStatusForRecipientUserID(
		ctx, noIdentity.ID, noIdentity.RecipientUserID, invites.InviteStatusAccepted, nil,
	); !errors.Is(err, invites.ErrInvalidAcceptedIdentity) {
		t.Errorf("UpdateStatusForRecipientUserID accepted without identity: expected ErrInvalidAcceptedIdentity, got %v", err)
	}

	got, err := r.IncomingInvites.GetByIDForRecipientUserID(ctx, noIdentity.ID, noIdentity.RecipientUserID)
	if err != nil {
		t.Fatalf("GetByIDForRecipientUserID after rejected update: %v", err)
	}

	if got.Status != invites.InviteStatusPending {
		t.Errorf("Status after rejected update: expected %q, got %q", invites.InviteStatusPending, got.Status)
	}

	if got.SenderUserID != "" {
		t.Errorf("SenderUserID after rejected update: expected empty, got %q", got.SenderUserID)
	}

	if got.SenderFQDNNormalized != "" {
		t.Errorf("SenderFQDNNormalized after rejected update: expected empty, got %q", got.SenderFQDNNormalized)
	}
}

// assertIncomingInviteDelete checks delete removes the invite for the recipient.
func assertIncomingInviteDelete(t *testing.T, ctx context.Context, r *repos.Repos, invite *invitesincoming.IncomingInvite) {
	t.Helper()

	if err := r.IncomingInvites.DeleteForRecipientUserID(ctx, invite.ID, invite.RecipientUserID); err != nil {
		t.Fatalf("DeleteForRecipientUserID: %v", err)
	}

	_, err := r.IncomingInvites.GetByIDForRecipientUserID(ctx, invite.ID, invite.RecipientUserID)
	if !errors.Is(err, invites.ErrInviteNotFound) {
		t.Errorf("GetByIDForRecipientUserID after delete: expected ErrInviteNotFound, got %v", err)
	}
}

func runIncomingInviteRepoContractListByRecipientUserID(t *testing.T, ctx context.Context, r *repos.Repos) {
	t.Helper()

	invite := &invitesincoming.IncomingInvite{
		ID:              "ct-list-in-inv-1",
		Token:           "ct-list-in-token-1",
		InviteString:    "b64ct-list-in",
		SenderFQDN:      "ct.list.sender.invite.example",
		RecipientUserID: "ct-list-recipient-user",
		Status:          invites.InviteStatusPending,
		ReceivedAt:      time.Unix(time.Now().Unix(), 0).UTC(),
	}
	if err := r.IncomingInvites.Create(ctx, invite); err != nil {
		t.Fatalf("Create: %v", err)
	}

	all, err := r.IncomingInvites.ListByRecipientUserID(ctx, invite.RecipientUserID)
	if err != nil {
		t.Fatalf("ListByRecipientUserID: %v", err)
	}

	found := false

	for _, inv := range all {
		if inv.ID == invite.ID {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("ListByRecipientUserID: created invite %q not found in result", invite.ID)
	}

	others, err := r.IncomingInvites.ListByRecipientUserID(ctx, "ct-another-user-entirely")
	if err != nil {
		t.Fatalf("ListByRecipientUserID other user: %v", err)
	}

	for _, inv := range others {
		if inv.ID == invite.ID {
			t.Errorf("ListByRecipientUserID: invite %q leaked to other user", invite.ID)
		}
	}
}

func runIncomingInviteRepoContractEnforcesRecipientScope(t *testing.T, ctx context.Context, r *repos.Repos) {
	t.Helper()

	invite := &invitesincoming.IncomingInvite{
		ID:              "ct-scope-in-inv-1",
		Token:           "ct-scope-in-token-1",
		InviteString:    "b64ct-scope",
		SenderFQDN:      "ct.scope.sender.invite.example",
		RecipientUserID: "ct-scope-inv-owner",
		Status:          invites.InviteStatusPending,
		ReceivedAt:      time.Unix(time.Now().Unix(), 0).UTC(),
	}
	if err := r.IncomingInvites.Create(ctx, invite); err != nil {
		t.Fatalf("Create: %v", err)
	}

	_, err := r.IncomingInvites.GetByIDForRecipientUserID(ctx, invite.ID, "ct-inv-wrong-user")
	if !errors.Is(err, invites.ErrInviteNotFound) {
		t.Errorf("GetByIDForRecipientUserID wrong user: expected ErrInviteNotFound, got %v", err)
	}

	_, err = r.IncomingInvites.GetByTokenForRecipientUserID(ctx, invite.Token, "ct-inv-wrong-user")
	if !errors.Is(err, invites.ErrInviteNotFound) {
		t.Errorf("GetByTokenForRecipientUserID wrong user: expected ErrInviteNotFound, got %v", err)
	}

	err = r.IncomingInvites.UpdateStatusForRecipientUserID(
		ctx, invite.ID, "ct-inv-wrong-user", invites.InviteStatusAccepted, nil,
	)
	if !errors.Is(err, invites.ErrInviteNotFound) {
		t.Errorf("UpdateStatusForRecipientUserID wrong user: expected ErrInviteNotFound, got %v", err)
	}

	err = r.IncomingInvites.DeleteForRecipientUserID(ctx, invite.ID, "ct-inv-wrong-user")
	if !errors.Is(err, invites.ErrInviteNotFound) {
		t.Errorf("DeleteForRecipientUserID wrong user: expected ErrInviteNotFound, got %v", err)
	}
}

func runIncomingInviteRepoContractAutoFill(t *testing.T, ctx context.Context, r *repos.Repos) {
	t.Helper()

	invite := &invitesincoming.IncomingInvite{
		Token:           "ct-autofill-in-token",
		InviteString:    "b64ct-autofill-in",
		SenderFQDN:      "ct.autofill.sender.invite.example",
		RecipientUserID: "ct-autofill-in-recipient",
	}
	if err := r.IncomingInvites.Create(ctx, invite); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if invite.ID == "" {
		t.Error("ID not auto-filled after Create")
	}

	if invite.ReceivedAt.IsZero() {
		t.Error("ReceivedAt not auto-filled after Create")
	}

	if invite.Status == "" {
		t.Error("Status not auto-filled after Create")
	}
}

func runIncomingInviteRepoContractIDNotFoundSentinel(t *testing.T, ctx context.Context, r *repos.Repos) {
	t.Helper()

	_, err := r.IncomingInvites.GetByIDForRecipientUserID(ctx, "ct-in-missing-invite-id", "any-user")
	if !errors.Is(err, invites.ErrInviteNotFound) {
		t.Errorf("GetByIDForRecipientUserID nonexistent: expected ErrInviteNotFound, got %v", err)
	}
}

// runOutgoingInviteRepoContract verifies CRUD, list, auto-fill, token/ID
// sentinel behaviour for the OutgoingInviteRepo interface.
func runOutgoingInviteRepoContract(t *testing.T, r *repos.Repos) {
	t.Helper()

	ctx := context.Background()

	t.Run("CRUD", func(t *testing.T) { runOutgoingInviteRepoContractCRUD(t, ctx, r) })
	t.Run("List", func(t *testing.T) { runOutgoingInviteRepoContractList(t, ctx, r) })
	t.Run("AutoFill", func(t *testing.T) { runOutgoingInviteRepoContractAutoFill(t, ctx, r) })
	t.Run("TokenSentinel", func(t *testing.T) { runOutgoingInviteRepoContractTokenSentinel(t, ctx, r) })
	t.Run("IDNotFoundSentinel", func(t *testing.T) { runOutgoingInviteRepoContractIDNotFoundSentinel(t, ctx, r) })
}

func runOutgoingInviteRepoContractCRUD(t *testing.T, ctx context.Context, r *repos.Repos) {
	t.Helper()

	now := time.Unix(time.Now().Unix(), 0).UTC()

	invite := &invitesoutgoing.OutgoingInvite{
		ID:              "ct-out-inv-1",
		Token:           "ct-out-token-1",
		ProviderFQDN:    "ct.provider.example",
		InviteString:    "b64ct-out",
		RecipientEmail:  "alice@ct.example",
		CreatedByUserID: "ct-creator-1",
		CreatedAt:       now,
		ExpiresAt:       now.Add(24 * time.Hour),
		Status:          invites.InviteStatusPending,
	}
	if err := r.OutgoingInvites.Create(ctx, invite); err != nil {
		t.Fatalf("Create: %v", err)
	}

	assertOutgoingInviteReadPaths(t, ctx, r, invite)
	acceptOutgoingInvite(t, ctx, r, invite)
	assertOutgoingAcceptedState(t, ctx, r, invite)
	assertOutgoingAcceptedScopeMisses(t, ctx, r, invite.CreatedByUserID)
	assertOutgoingCreateRejectedAcceptedWithoutIdentity(t, ctx, r, now)
	assertOutgoingUpdateRejectedWithoutNormalized(t, ctx, r, now)
}

// assertOutgoingInviteReadPaths checks the ID and token read paths return the
// created invite.
func assertOutgoingInviteReadPaths(t *testing.T, ctx context.Context, r *repos.Repos, invite *invitesoutgoing.OutgoingInvite) {
	t.Helper()

	got, err := r.OutgoingInvites.GetByID(ctx, invite.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}

	if got.Token != invite.Token {
		t.Errorf("Token: got %q, want %q", got.Token, invite.Token)
	}

	got, err = r.OutgoingInvites.GetByToken(ctx, invite.Token)
	if err != nil {
		t.Fatalf("GetByToken: %v", err)
	}

	if got.ID != invite.ID {
		t.Errorf("GetByToken ID: got %q, want %q", got.ID, invite.ID)
	}
}

// acceptOutgoingInvite marks the invite accepted with provider identity.
func acceptOutgoingInvite(t *testing.T, ctx context.Context, r *repos.Repos, invite *invitesoutgoing.OutgoingInvite) {
	t.Helper()

	acceptance := &invitesoutgoing.Acceptance{
		ProviderFQDN:           "ct.provider.example",
		UserID:                 "ct-acceptor-user-1",
		ProviderFQDNNormalized: "ct.provider.example",
	}

	if err := r.OutgoingInvites.UpdateStatus(
		ctx, invite.ID, invites.InviteStatusAccepted, acceptance,
	); err != nil {
		t.Fatalf("UpdateStatus: %v", err)
	}
}

// assertOutgoingAcceptedState checks post-accept persisted state and the
// accepted-recipient lookup.
func assertOutgoingAcceptedState(t *testing.T, ctx context.Context, r *repos.Repos, invite *invitesoutgoing.OutgoingInvite) {
	t.Helper()

	got, err := r.OutgoingInvites.GetByID(ctx, invite.ID)
	if err != nil {
		t.Fatalf("GetByID after UpdateStatus: %v", err)
	}

	if got.Status != invites.InviteStatusAccepted {
		t.Errorf("Status after update: got %q, want accepted", got.Status)
	}

	if got.AcceptedProviderFQDN != "ct.provider.example" {
		t.Errorf("AcceptedProviderFQDN: got %q, want ct.provider.example", got.AcceptedProviderFQDN)
	}

	if got.AcceptedUserID != "ct-acceptor-user-1" {
		t.Errorf("AcceptedUserID: got %q, want ct-acceptor-user-1", got.AcceptedUserID)
	}

	if got.AcceptedProviderFQDNNormalized != "ct.provider.example" {
		t.Errorf("AcceptedProviderFQDNNormalized: got %q, want ct.provider.example", got.AcceptedProviderFQDNNormalized)
	}

	if got.AcceptedAt == nil {
		t.Error("AcceptedAt: expected non-nil after acceptance")
	}

	found, err := r.OutgoingInvites.FindAcceptedForRecipient(ctx, invite.CreatedByUserID, "ct-acceptor-user-1", "ct.provider.example")
	if err != nil {
		t.Fatalf("FindAcceptedForRecipient: %v", err)
	}

	if found.ID != invite.ID {
		t.Errorf("FindAcceptedForRecipient ID: got %q, want %q", found.ID, invite.ID)
	}
}

// assertOutgoingAcceptedScopeMisses checks wrong host, user, or creator
// queries never match the accepted invite.
func assertOutgoingAcceptedScopeMisses(t *testing.T, ctx context.Context, r *repos.Repos, createdByUserID string) {
	t.Helper()

	cases := []struct {
		name         string
		creator      string
		acceptorUser string
		providerFQDN string
	}{
		{"wrong host", createdByUserID, "ct-acceptor-user-1", "other.example"},
		{"wrong user", createdByUserID, "ct-other-acceptor", "ct.provider.example"},
		{"wrong creator", "ct-other-creator", "ct-acceptor-user-1", "ct.provider.example"},
	}

	for _, tc := range cases {
		if _, err := r.OutgoingInvites.FindAcceptedForRecipient(
			ctx, tc.creator, tc.acceptorUser, tc.providerFQDN,
		); !errors.Is(err, invites.ErrInviteNotFound) {
			t.Errorf("FindAcceptedForRecipient %s: expected ErrInviteNotFound, got %v", tc.name, err)
		}
	}
}

// assertOutgoingCreateRejectedAcceptedWithoutIdentity checks that creating an
// outgoing invite directly in accepted status without accepted identity is
// rejected with ErrInvalidCreateStatus across every backend.
func assertOutgoingCreateRejectedAcceptedWithoutIdentity(t *testing.T, ctx context.Context, r *repos.Repos, now time.Time) {
	t.Helper()

	invite := &invitesoutgoing.OutgoingInvite{
		ID:              "ct-out-inv-create-accepted",
		Token:           "ct-out-token-create-accepted",
		ProviderFQDN:    "ct.create-accepted.example",
		InviteString:    "b64ct-out-create-accepted",
		CreatedByUserID: "ct-creator-create-accepted",
		CreatedAt:       now,
		ExpiresAt:       now.Add(24 * time.Hour),
		Status:          invites.InviteStatusAccepted,
	}
	if err := r.OutgoingInvites.Create(ctx, invite); !errors.Is(err, invites.ErrInvalidCreateStatus) {
		t.Errorf("Create accepted without identity: expected ErrInvalidCreateStatus, got %v", err)
	}
}

// assertOutgoingUpdateRejectedWithoutNormalized checks an accepted update
// missing the normalized provider host is rejected with
// ErrInvalidAcceptedIdentity and that the stored row is left untouched (no
// partial write leaks through).
func assertOutgoingUpdateRejectedWithoutNormalized(t *testing.T, ctx context.Context, r *repos.Repos, now time.Time) {
	t.Helper()

	noNorm := &invitesoutgoing.OutgoingInvite{
		ID:              "ct-out-inv-nonorm",
		Token:           "ct-out-token-nonorm",
		ProviderFQDN:    "ct.nonorm.example",
		InviteString:    "b64ct-out-nonorm",
		CreatedByUserID: "ct-creator-nonorm",
		CreatedAt:       now,
		ExpiresAt:       now.Add(24 * time.Hour),
		Status:          invites.InviteStatusPending,
	}
	if err := r.OutgoingInvites.Create(ctx, noNorm); err != nil {
		t.Fatalf("Create noNorm: %v", err)
	}

	if err := r.OutgoingInvites.UpdateStatus(
		ctx, noNorm.ID, invites.InviteStatusAccepted, &invitesoutgoing.Acceptance{UserID: "ct-nonorm-acceptor"},
	); !errors.Is(err, invites.ErrInvalidAcceptedIdentity) {
		t.Errorf("UpdateStatus accepted without normalized host: expected ErrInvalidAcceptedIdentity, got %v", err)
	}

	got, err := r.OutgoingInvites.GetByID(ctx, noNorm.ID)
	if err != nil {
		t.Fatalf("GetByID after rejected update: %v", err)
	}

	if got.Status != invites.InviteStatusPending {
		t.Errorf("Status after rejected update: expected %q, got %q", invites.InviteStatusPending, got.Status)
	}

	if got.AcceptedUserID != "" {
		t.Errorf("AcceptedUserID after rejected update: expected empty, got %q", got.AcceptedUserID)
	}

	if got.AcceptedProviderFQDNNormalized != "" {
		t.Errorf("AcceptedProviderFQDNNormalized after rejected update: expected empty, got %q", got.AcceptedProviderFQDNNormalized)
	}
}

// runOutgoingInviteRepoContractAcceptedIdentityCoalescedOnEmptyUpdate
// verifies that re-accepting an already-accepted outgoing invite with an empty
// identity payload preserves the persisted accepted identity: the user id and
// normalized host coalesce from the stored row so a partial write cannot erase
// them, and the raw provider FQDN is not overwritten by the empty payload.
func runOutgoingInviteRepoContractAcceptedIdentityCoalescedOnEmptyUpdate(t *testing.T, ctx context.Context, r *repos.Repos) {
	t.Helper()

	now := time.Unix(time.Now().Unix(), 0).UTC()

	invite := &invitesoutgoing.OutgoingInvite{
		ID:              "ct-out-inv-empty-update",
		Token:           "ct-out-token-empty-update",
		ProviderFQDN:    "ct.empty.example",
		InviteString:    "b64ct-out-empty-update",
		RecipientEmail:  "alice@ct.example",
		CreatedByUserID: "ct-creator-empty-update",
		CreatedAt:       now,
		ExpiresAt:       now.Add(24 * time.Hour),
		Status:          invites.InviteStatusPending,
	}
	if err := r.OutgoingInvites.Create(ctx, invite); err != nil {
		t.Fatalf("Create: %v", err)
	}

	acceptance := &invitesoutgoing.Acceptance{
		ProviderFQDN:           "ct.empty.example",
		UserID:                 "ct-acceptor-empty-update",
		ProviderFQDNNormalized: "ct.empty.example",
	}
	if err := r.OutgoingInvites.UpdateStatus(
		ctx, invite.ID, invites.InviteStatusAccepted, acceptance,
	); err != nil {
		t.Fatalf("UpdateStatus accepted with identity: %v", err)
	}

	// Re-accept with an empty identity payload: the coalesced identity must keep
	// the stored row, and the raw provider FQDN must not be written back from the
	// empty payload.
	emptyAcceptance := &invitesoutgoing.Acceptance{}
	if err := r.OutgoingInvites.UpdateStatus(
		ctx, invite.ID, invites.InviteStatusAccepted, emptyAcceptance,
	); err != nil {
		t.Fatalf("UpdateStatus accepted with empty identity: %v", err)
	}

	got, err := r.OutgoingInvites.GetByID(ctx, invite.ID)
	if err != nil {
		t.Fatalf("GetByID after empty update: %v", err)
	}

	if got.Status != invites.InviteStatusAccepted {
		t.Errorf("Status after empty update: got %q, want accepted", got.Status)
	}

	if got.AcceptedUserID != acceptance.UserID {
		t.Errorf("AcceptedUserID after empty update: got %q, want %q (coalesced from stored, not overwritten by empty)", got.AcceptedUserID, acceptance.UserID)
	}

	if got.AcceptedProviderFQDNNormalized != acceptance.ProviderFQDNNormalized {
		t.Errorf("AcceptedProviderFQDNNormalized after empty update: got %q, want %q (coalesced from stored, not overwritten by empty)", got.AcceptedProviderFQDNNormalized, acceptance.ProviderFQDNNormalized)
	}

	if got.AcceptedProviderFQDN != acceptance.ProviderFQDN {
		t.Errorf("AcceptedProviderFQDN after empty update: got %q, want %q (raw FQDN not written back from empty payload)", got.AcceptedProviderFQDN, acceptance.ProviderFQDN)
	}
}

// runIncomingInviteRepoContractAcceptedIdentityCoalescedOnEmptyUpdate
// verifies that re-accepting an already-accepted incoming invite with an empty
// identity payload preserves the persisted sender identity: the user id and
// normalized host coalesce from the stored row so a partial write cannot erase
// them, and the raw sender FQDN is not overwritten by the empty payload.
func runIncomingInviteRepoContractAcceptedIdentityCoalescedOnEmptyUpdate(t *testing.T, ctx context.Context, r *repos.Repos) {
	t.Helper()

	invite := &invitesincoming.IncomingInvite{
		ID:              "ct-in-inv-empty-update",
		Token:           "ct-in-token-empty-update",
		InviteString:    "b64ct-in-empty-update",
		SenderFQDN:      "ct.empty.example",
		RecipientUserID: "ct-recipient-empty-update",
		Status:          invites.InviteStatusPending,
		ReceivedAt:      time.Unix(time.Now().Unix(), 0).UTC(),
	}
	if err := r.IncomingInvites.Create(ctx, invite); err != nil {
		t.Fatalf("Create: %v", err)
	}

	acceptance := &invitesincoming.Acceptance{
		UserID:                 "ct-sender-empty-update",
		ProviderFQDNNormalized: "ct.empty.example",
	}
	if err := r.IncomingInvites.UpdateStatusForRecipientUserID(
		ctx, invite.ID, invite.RecipientUserID, invites.InviteStatusAccepted, acceptance,
	); err != nil {
		t.Fatalf("UpdateStatusForRecipientUserID accepted with identity: %v", err)
	}

	// Re-accept with an empty identity payload: the coalesced identity must keep
	// the stored row, and the raw sender FQDN must not be written back from the
	// empty payload.
	emptyAcceptance := &invitesincoming.Acceptance{}
	if err := r.IncomingInvites.UpdateStatusForRecipientUserID(
		ctx, invite.ID, invite.RecipientUserID, invites.InviteStatusAccepted, emptyAcceptance,
	); err != nil {
		t.Fatalf("UpdateStatusForRecipientUserID accepted with empty identity: %v", err)
	}

	got, err := r.IncomingInvites.GetByIDForRecipientUserID(ctx, invite.ID, invite.RecipientUserID)
	if err != nil {
		t.Fatalf("GetByIDForRecipientUserID after empty update: %v", err)
	}

	if got.Status != invites.InviteStatusAccepted {
		t.Errorf("Status after empty update: got %q, want accepted", got.Status)
	}

	if got.SenderUserID != acceptance.UserID {
		t.Errorf("SenderUserID after empty update: got %q, want %q (coalesced from stored, not overwritten by empty)", got.SenderUserID, acceptance.UserID)
	}

	if got.SenderFQDNNormalized != acceptance.ProviderFQDNNormalized {
		t.Errorf("SenderFQDNNormalized after empty update: got %q, want %q (coalesced from stored, not overwritten by empty)", got.SenderFQDNNormalized, acceptance.ProviderFQDNNormalized)
	}

	if got.SenderFQDN != invite.SenderFQDN {
		t.Errorf("SenderFQDN after empty update: got %q, want %q (raw FQDN not written back from empty payload)", got.SenderFQDN, invite.SenderFQDN)
	}
}

func runOutgoingInviteRepoContractList(t *testing.T, ctx context.Context, r *repos.Repos) {
	t.Helper()

	now := time.Unix(time.Now().Unix(), 0).UTC()
	inviteA := &invitesoutgoing.OutgoingInvite{
		ID:              "ct-list-out-inv-1",
		Token:           "ct-list-out-token-1",
		ProviderFQDN:    "ct.list.provider.example",
		InviteString:    "b64ct-list-out-1",
		CreatedByUserID: "ct-list-creator-A",
		CreatedAt:       now,
		ExpiresAt:       now.Add(24 * time.Hour),
		Status:          invites.InviteStatusPending,
	}
	inviteB := &invitesoutgoing.OutgoingInvite{
		ID:              "ct-list-out-inv-2",
		Token:           "ct-list-out-token-2",
		ProviderFQDN:    "ct.list.provider.example",
		InviteString:    "b64ct-list-out-2",
		CreatedByUserID: "ct-list-creator-B",
		CreatedAt:       now,
		ExpiresAt:       now.Add(24 * time.Hour),
		Status:          invites.InviteStatusPending,
	}

	if err := r.OutgoingInvites.Create(ctx, inviteA); err != nil {
		t.Fatalf("Create inviteA: %v", err)
	}

	if err := r.OutgoingInvites.Create(ctx, inviteB); err != nil {
		t.Fatalf("Create inviteB: %v", err)
	}

	all, err := r.OutgoingInvites.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	foundA, foundB := false, false

	for _, inv := range all {
		switch inv.ID {
		case inviteA.ID:
			foundA = true
		case inviteB.ID:
			foundB = true
		}
	}

	if !foundA {
		t.Errorf("List: invite %q (creator-A) not found; List must return all invites, not creator-filtered", inviteA.ID)
	}

	if !foundB {
		t.Errorf("List: invite %q (creator-B) not found; List must return all invites, not creator-filtered", inviteB.ID)
	}
}

func runOutgoingInviteRepoContractAutoFill(t *testing.T, ctx context.Context, r *repos.Repos) {
	t.Helper()

	now := time.Unix(time.Now().Unix(), 0).UTC()

	invite := &invitesoutgoing.OutgoingInvite{
		Token:        "ct-autofill-out-token",
		ProviderFQDN: "ct.autofill.provider.example",
		InviteString: "b64ct-autofill-out",
		CreatedAt:    now,
		ExpiresAt:    now.Add(24 * time.Hour),
	}
	if err := r.OutgoingInvites.Create(ctx, invite); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if invite.ID == "" {
		t.Error("ID not auto-filled after Create")
	}

	if invite.Status == "" {
		t.Error("Status not auto-filled after Create")
	}
}

func runOutgoingInviteRepoContractTokenSentinel(t *testing.T, ctx context.Context, r *repos.Repos) {
	t.Helper()

	_, err := r.OutgoingInvites.GetByToken(ctx, "ct-out-missing-token")
	if !errors.Is(err, invites.ErrTokenNotFound) {
		t.Errorf("GetByToken nonexistent: expected ErrTokenNotFound, got %v", err)
	}
}

func runOutgoingInviteRepoContractIDNotFoundSentinel(t *testing.T, ctx context.Context, r *repos.Repos) {
	t.Helper()

	_, err := r.OutgoingInvites.GetByID(ctx, "ct-out-missing-invite-id")
	if !errors.Is(err, invites.ErrInviteNotFound) {
		t.Errorf("GetByID nonexistent: expected ErrInviteNotFound, got %v", err)
	}
}
