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
	invitesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/repos"
)

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
