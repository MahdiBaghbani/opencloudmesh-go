// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package store

import (
	"context"
	"errors"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
)

func runOutgoingInviteCRUD(t *testing.T, ctx context.Context, s store.OutgoingInviteStore) {
	t.Helper()

	invite := NewOutgoingInviteFixture()

	createOutgoingInvite(t, ctx, s, invite)
	requireDuplicateCreateOutgoingInviteFails(t, ctx, s, invite)
	requireOutgoingInviteByID(t, ctx, s, invite)
	requireOutgoingInviteByToken(t, ctx, s, invite)
	oldToken := updateOutgoingInviteToken(t, ctx, s, invite, "new-invite-token")
	updateOutgoingInviteStatusAccepted(t, ctx, s, invite)
	requireOutgoingInviteByTokenNotFound(t, ctx, s, oldToken)
	requireOutgoingInviteByTokenHasStatus(t, ctx, s, invite.Token, fixtureStatusAccepted)
	requireOutgoingInviteListByUserNonEmpty(t, ctx, s, invite.CreatedByUserID)
	deleteOutgoingInvite(t, ctx, s, invite.ID)
	requireOutgoingInviteNotFound(t, ctx, s, invite.ID)
}

func createOutgoingInvite(t *testing.T, ctx context.Context, s store.OutgoingInviteStore, invite *store.OutgoingInvite) {
	t.Helper()

	if err := s.CreateOutgoingInvite(ctx, invite); err != nil {
		t.Fatalf("CreateOutgoingInvite failed: %v", err)
	}

	t.Cleanup(func() {
		if err := s.DeleteOutgoingInvite(ctx, invite.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
			t.Errorf("cleanup: DeleteOutgoingInvite: %v", err)
		}
	})
}

func requireDuplicateCreateOutgoingInviteFails(t *testing.T, ctx context.Context, s store.OutgoingInviteStore, invite *store.OutgoingInvite) {
	t.Helper()

	if err := s.CreateOutgoingInvite(ctx, invite); !errors.Is(err, store.ErrAlreadyExists) {
		t.Errorf("expected ErrAlreadyExists on duplicate create, got %v", err)
	}
}

func requireOutgoingInviteByID(t *testing.T, ctx context.Context, s store.OutgoingInviteStore, invite *store.OutgoingInvite) {
	t.Helper()

	got, err := s.GetOutgoingInvite(ctx, invite.ID)
	if err != nil {
		t.Fatalf("GetOutgoingInvite failed: %v", err)
	}

	if got.Token != invite.Token {
		t.Errorf("expected token %q, got %q", invite.Token, got.Token)
	}
}

func requireOutgoingInviteByToken(t *testing.T, ctx context.Context, s store.OutgoingInviteStore, invite *store.OutgoingInvite) {
	t.Helper()

	got, err := s.GetOutgoingInviteByToken(ctx, invite.Token)
	if err != nil {
		t.Fatalf("GetOutgoingInviteByToken failed: %v", err)
	}

	if got.ID != invite.ID {
		t.Errorf("expected id %q, got %q", invite.ID, got.ID)
	}
}

func updateOutgoingInviteToken(
	t *testing.T,
	ctx context.Context,
	s store.OutgoingInviteStore,
	invite *store.OutgoingInvite,
	newToken string,
) string {
	t.Helper()

	oldToken := invite.Token
	invite.Token = newToken

	if err := s.UpdateOutgoingInvite(ctx, invite); err != nil {
		t.Fatalf("UpdateOutgoingInvite failed: %v", err)
	}

	return oldToken
}

func updateOutgoingInviteStatusAccepted(t *testing.T, ctx context.Context, s store.OutgoingInviteStore, invite *store.OutgoingInvite) {
	t.Helper()

	invite.Status = fixtureStatusAccepted
	invite.AcceptedUserID = fixtureUserBob
	invite.AcceptedProviderFQDNNormalized = invite.ProviderFQDN

	if err := s.UpdateOutgoingInvite(ctx, invite); err != nil {
		t.Fatalf("UpdateOutgoingInvite failed: %v", err)
	}
}

func requireOutgoingInviteByTokenNotFound(t *testing.T, ctx context.Context, s store.OutgoingInviteStore, token string) {
	t.Helper()

	_, err := s.GetOutgoingInviteByToken(ctx, token)
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected ErrNotFound for stale token after update, got %v", err)
	}
}

func requireOutgoingInviteByTokenHasStatus(t *testing.T, ctx context.Context, s store.OutgoingInviteStore, token, want string) {
	t.Helper()

	got, err := s.GetOutgoingInviteByToken(ctx, token)
	if err != nil {
		t.Fatalf("GetOutgoingInviteByToken for new token failed: %v", err)
	}

	if got.Status != want {
		t.Errorf("expected status %q, got %q", want, got.Status)
	}
}

func requireOutgoingInviteListByUserNonEmpty(t *testing.T, ctx context.Context, s store.OutgoingInviteStore, userID string) {
	t.Helper()

	invites, err := s.ListOutgoingInvites(ctx, userID)
	if err != nil {
		t.Fatalf("ListOutgoingInvites failed: %v", err)
	}

	if len(invites) == 0 {
		t.Error("expected at least one invite in list")
	}
}

func deleteOutgoingInvite(t *testing.T, ctx context.Context, s store.OutgoingInviteStore, id string) {
	t.Helper()

	if err := s.DeleteOutgoingInvite(ctx, id); err != nil {
		t.Fatalf("DeleteOutgoingInvite failed: %v", err)
	}
}

func requireOutgoingInviteNotFound(t *testing.T, ctx context.Context, s store.OutgoingInviteStore, id string) {
	t.Helper()

	_, err := s.GetOutgoingInvite(ctx, id)
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected ErrNotFound after delete, got %v", err)
	}
}

// runOutgoingInviteUpdateNotFound verifies that UpdateOutgoingInvite returns
// ErrNotFound when the target record does not exist.
func runOutgoingInviteUpdateNotFound(
	t *testing.T,
	ctx context.Context,
	s store.OutgoingInviteStore,
) {
	t.Helper()

	ghost := NewOutgoingInviteFixture()
	ghost.ID = "update-missing-out-invite-id"

	if err := s.UpdateOutgoingInvite(ctx, ghost); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected ErrNotFound for update of missing outgoing invite, got %v", err)
	}
}

// runOutgoingInviteAcceptedIdentityCoalescedOnEmptyUpdate verifies the store
// layer (without the adapter) coalesces an empty-identity accepted update with
// the stored row so a partial write cannot erase the accepted identity. The
// store coalesces only AcceptedUserID and AcceptedProviderFQDNNormalized;
// the raw AcceptedProviderFQDN follows replace semantics and is not restored
// from the stored row when the payload carries an empty value.
func runOutgoingInviteAcceptedIdentityCoalescedOnEmptyUpdate(t *testing.T, ctx context.Context, s store.OutgoingInviteStore) {
	t.Helper()

	invite := NewOutgoingInviteFixture()
	invite.ID = "store-out-coalesce-id"
	invite.Token = "store-out-coalesce-token"
	invite.Status = fixtureStatusPending
	invite.AcceptedUserID = ""
	invite.AcceptedProviderFQDNNormalized = ""
	invite.AcceptedProviderFQDN = ""

	createOutgoingInvite(t, ctx, s, invite)

	invite.Status = fixtureStatusAccepted
	invite.AcceptedUserID = "store-acceptor"
	invite.AcceptedProviderFQDNNormalized = invite.ProviderFQDN
	invite.AcceptedProviderFQDN = invite.ProviderFQDN

	if err := s.UpdateOutgoingInvite(ctx, invite); err != nil {
		t.Fatalf("UpdateOutgoingInvite accepted with identity: %v", err)
	}

	// Re-accept with an entirely empty accepted-identity payload: the store
	// must coalesce userID and normalizedHost from the stored row, but must
	// NOT restore the raw AcceptedProviderFQDN (replace semantics).
	invite.AcceptedUserID = ""
	invite.AcceptedProviderFQDNNormalized = ""
	invite.AcceptedProviderFQDN = ""

	if err := s.UpdateOutgoingInvite(ctx, invite); err != nil {
		t.Fatalf("UpdateOutgoingInvite accepted with empty identity: %v", err)
	}

	got, err := s.GetOutgoingInvite(ctx, invite.ID)
	if err != nil {
		t.Fatalf("GetOutgoingInvite after empty update: %v", err)
	}

	if got.Status != fixtureStatusAccepted {
		t.Errorf("Status after empty update: got %q, want accepted", got.Status)
	}

	if got.AcceptedUserID != "store-acceptor" {
		t.Errorf("AcceptedUserID after empty update: got %q, want store-acceptor (coalesced from stored)", got.AcceptedUserID)
	}

	if got.AcceptedProviderFQDNNormalized != invite.ProviderFQDN {
		t.Errorf("AcceptedProviderFQDNNormalized after empty update: got %q, want %q (coalesced from stored)", got.AcceptedProviderFQDNNormalized, invite.ProviderFQDN)
	}

	// Option B: the raw FQDN is not coalesced. An empty payload value replaces
	// the stored raw FQDN; the store must not restore it from the stored row.
	if got.AcceptedProviderFQDN != "" {
		t.Errorf("AcceptedProviderFQDN after empty update: got %q, want empty (raw FQDN follows replace semantics, not coalesced)", got.AcceptedProviderFQDN)
	}
}
