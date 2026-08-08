// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
)

// runIncomingInviteStatusContract verifies incoming-invite update behavior:
// cross-user access is rejected, scope-defining fields (Token, RecipientUserID)
// are unchanged after an update, and the remote sender identity is persisted on
// acceptance.
func runIncomingInviteStatusContract(t *testing.T, ctx context.Context, s store.IncomingInviteStore) {
	t.Helper()

	invite := NewIncomingInviteFixture()

	createIncomingInvite(t, ctx, s, invite)
	requireIncomingInviteForRecipient(t, ctx, s, invite)
	requireIncomingInviteNotFoundForRecipient(t, ctx, s, invite.ID, "other-user")
	requireIncomingInviteByTokenForRecipient(t, ctx, s, invite)
	requireIncomingInviteByTokenNotFoundForRecipient(t, ctx, s, invite.Token, "other-user")
	updateIncomingInviteStatusAndAssert(t, ctx, s, invite, fixtureStatusAccepted)
	requireIncomingInviteStatusUpdateNotFoundForRecipient(t, ctx, s, invite.ID, "other-user", "declined")
	requireIncomingInviteByTokenHasStatus(t, ctx, s, invite.Token, invite.RecipientUserID, fixtureStatusAccepted)
	requireIncomingInviteListByRecipientNonEmpty(t, ctx, s, invite.RecipientUserID)
	requireIncomingInviteDeleteNotFoundForRecipient(t, ctx, s, invite.ID, "other-user")
	deleteIncomingInviteForRecipient(t, ctx, s, invite.ID, invite.RecipientUserID)
	requireIncomingInviteNotFoundForRecipient(t, ctx, s, invite.ID, invite.RecipientUserID)
}

func createIncomingInvite(t *testing.T, ctx context.Context, s store.IncomingInviteStore, invite *store.IncomingInvite) {
	t.Helper()

	if err := s.CreateIncomingInvite(ctx, invite); err != nil {
		t.Fatalf("CreateIncomingInvite failed: %v", err)
	}

	t.Cleanup(func() {
		if err := s.DeleteIncomingInviteForRecipient(ctx, invite.ID, invite.RecipientUserID); err != nil && !errors.Is(err, store.ErrNotFound) {
			t.Errorf("cleanup: DeleteIncomingInviteForRecipient: %v", err)
		}
	})
}

func requireIncomingInviteForRecipient(t *testing.T, ctx context.Context, s store.IncomingInviteStore, invite *store.IncomingInvite) {
	t.Helper()

	got, err := s.GetIncomingInviteForRecipient(ctx, invite.ID, invite.RecipientUserID)
	if err != nil {
		t.Fatalf("GetIncomingInviteForRecipient failed: %v", err)
	}

	if got.Token != invite.Token {
		t.Errorf("expected token %q, got %q", invite.Token, got.Token)
	}
}

func requireIncomingInviteNotFoundForRecipient(t *testing.T, ctx context.Context, s store.IncomingInviteStore, id, userID string) {
	t.Helper()

	_, err := s.GetIncomingInviteForRecipient(ctx, id, userID)
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected ErrNotFound for cross-user get, got %v", err)
	}
}

func requireIncomingInviteByTokenForRecipient(t *testing.T, ctx context.Context, s store.IncomingInviteStore, invite *store.IncomingInvite) {
	t.Helper()

	got, err := s.GetIncomingInviteByToken(ctx, invite.Token, invite.RecipientUserID)
	if err != nil {
		t.Fatalf("GetIncomingInviteByToken failed: %v", err)
	}

	if got.ID != invite.ID {
		t.Errorf("expected id %q, got %q", invite.ID, got.ID)
	}
}

func requireIncomingInviteByTokenNotFoundForRecipient(t *testing.T, ctx context.Context, s store.IncomingInviteStore, token, userID string) {
	t.Helper()

	_, err := s.GetIncomingInviteByToken(ctx, token, userID)
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected ErrNotFound for cross-user token lookup, got %v", err)
	}
}

func updateIncomingInviteStatusAndAssert(t *testing.T, ctx context.Context, s store.IncomingInviteStore, invite *store.IncomingInvite, state string) {
	t.Helper()

	beforeUpdate := time.Now().Unix()

	if err := s.UpdateIncomingInviteStatusForRecipient(ctx, invite.ID, invite.RecipientUserID, state, "ct-sender-user-1", "ct-sender.example.com"); err != nil {
		t.Fatalf("UpdateIncomingInviteStatusForRecipient failed: %v", err)
	}

	got, err := s.GetIncomingInviteForRecipient(ctx, invite.ID, invite.RecipientUserID)
	if err != nil {
		t.Fatalf("GetIncomingInviteForRecipient after update failed: %v", err)
	}

	if got.Status != state {
		t.Errorf("expected status %q after update, got %q", state, got.Status)
	}

	if got.Token != invite.Token {
		t.Errorf("token must not change on status update: expected %q, got %q", invite.Token, got.Token)
	}

	if got.RecipientUserID != invite.RecipientUserID {
		t.Errorf(
			"recipient must not change on status update: expected %q, got %q",
			invite.RecipientUserID,
			got.RecipientUserID,
		)
	}

	if got.SenderUserID != "ct-sender-user-1" {
		t.Errorf("expected sender user id persisted on status update, got %q", got.SenderUserID)
	}

	if got.SenderFQDNNormalized != "ct-sender.example.com" {
		t.Errorf("expected normalized sender fqdn persisted on status update, got %q", got.SenderFQDNNormalized)
	}

	if got.UpdatedAt < beforeUpdate {
		t.Errorf(
			"UpdatedAt not refreshed after status update: got %d, expected >= %d",
			got.UpdatedAt,
			beforeUpdate,
		)
	}
}

func requireIncomingInviteStatusUpdateNotFoundForRecipient(
	t *testing.T,
	ctx context.Context,
	s store.IncomingInviteStore,
	id,
	userID,
	state string,
) {
	t.Helper()

	err := s.UpdateIncomingInviteStatusForRecipient(ctx, id, userID, state, "", "")
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected ErrNotFound for cross-user status update, got %v", err)
	}
}

func requireIncomingInviteByTokenHasStatus(t *testing.T, ctx context.Context, s store.IncomingInviteStore, token, userID, want string) {
	t.Helper()

	got, err := s.GetIncomingInviteByToken(ctx, token, userID)
	if err != nil {
		t.Fatalf("GetIncomingInviteByToken must still work after status update: %v", err)
	}

	if got.Status != want {
		t.Errorf("expected updated status via token lookup, got %q", got.Status)
	}
}

func requireIncomingInviteListByRecipientNonEmpty(t *testing.T, ctx context.Context, s store.IncomingInviteStore, userID string) {
	t.Helper()

	invites, err := s.ListIncomingInvites(ctx, userID)
	if err != nil {
		t.Fatalf("ListIncomingInvites failed: %v", err)
	}

	if len(invites) == 0 {
		t.Error("expected at least one invite in list")
	}
}

func requireIncomingInviteDeleteNotFoundForRecipient(t *testing.T, ctx context.Context, s store.IncomingInviteStore, id, userID string) {
	t.Helper()

	err := s.DeleteIncomingInviteForRecipient(ctx, id, userID)
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected ErrNotFound for cross-user delete, got %v", err)
	}
}

func deleteIncomingInviteForRecipient(t *testing.T, ctx context.Context, s store.IncomingInviteStore, id, userID string) {
	t.Helper()

	if err := s.DeleteIncomingInviteForRecipient(ctx, id, userID); err != nil {
		t.Fatalf("DeleteIncomingInviteForRecipient failed: %v", err)
	}
}

// runIncomingInviteCompositeUniqueness verifies that (token, recipientUserID)
// is enforced as a composite unique key across all backends:
// - a duplicate pair returns ErrAlreadyExists
// - the original record is not replaced
// - the same token with a different recipient is allowed.
func runIncomingInviteCompositeUniqueness(
	t *testing.T,
	ctx context.Context,
	s store.IncomingInviteStore,
) {
	t.Helper()

	first := &store.IncomingInvite{
		ID:              "composite-unique-test-1",
		Token:           fixtureCompositeUniqueToken,
		InviteString:    fixtureInviteString,
		SenderFQDN:      fixtureRemoteExample,
		RecipientUserID: fixtureUserAlice,
		Status:          fixtureStatusPending,
		ReceivedAt:      time.Now().Unix(),
		UpdatedAt:       time.Now().Unix(),
	}
	if err := s.CreateIncomingInvite(ctx, first); err != nil {
		t.Fatalf("CreateIncomingInvite(first): %v", err)
	}

	t.Cleanup(func() {
		if err := s.DeleteIncomingInviteForRecipient(ctx, first.ID, first.RecipientUserID); err != nil && !errors.Is(err, store.ErrNotFound) {
			t.Errorf("cleanup: DeleteIncomingInviteForRecipient first: %v", err)
		}
	})

	// Same (token, recipientUserID), different ID: must fail.
	second := &store.IncomingInvite{
		ID:              "composite-unique-test-2",
		Token:           fixtureCompositeUniqueToken,
		InviteString:    fixtureInviteString,
		SenderFQDN:      fixtureRemoteExample,
		RecipientUserID: fixtureUserAlice,
		Status:          fixtureStatusPending,
		ReceivedAt:      time.Now().Unix(),
		UpdatedAt:       time.Now().Unix(),
	}
	if err := s.CreateIncomingInvite(ctx, second); !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("expected ErrAlreadyExists for duplicate (token, recipientUserID), got %v", err)
	}

	// Original must still be found by token lookup.
	got, err := s.GetIncomingInviteByToken(ctx, fixtureCompositeUniqueToken, fixtureUserAlice)
	if err != nil {
		t.Fatalf("GetIncomingInviteByToken after conflict: %v", err)
	}

	if got.ID != "composite-unique-test-1" {
		t.Errorf(
			"original invite overwritten: expected composite-unique-test-1, got %q",
			got.ID,
		)
	}

	// Same token, different recipient: must succeed.
	third := &store.IncomingInvite{
		ID:              "composite-unique-test-3",
		Token:           fixtureCompositeUniqueToken,
		InviteString:    fixtureInviteString,
		SenderFQDN:      fixtureRemoteExample,
		RecipientUserID: fixtureUserBob,
		Status:          fixtureStatusPending,
		ReceivedAt:      time.Now().Unix(),
		UpdatedAt:       time.Now().Unix(),
	}
	if createErr := s.CreateIncomingInvite(ctx, third); createErr != nil {
		t.Fatalf("CreateIncomingInvite(third, different recipient): %v", createErr)
	}

	t.Cleanup(func() {
		if deleteErr := s.DeleteIncomingInviteForRecipient(ctx, third.ID, third.RecipientUserID); deleteErr != nil && !errors.Is(deleteErr, store.ErrNotFound) {
			t.Errorf("cleanup: DeleteIncomingInviteForRecipient third: %v", deleteErr)
		}
	})

	gotBob, err := s.GetIncomingInviteByToken(ctx, fixtureCompositeUniqueToken, fixtureUserBob)
	if err != nil {
		t.Fatalf("GetIncomingInviteByToken for bob: %v", err)
	}

	if gotBob.ID != "composite-unique-test-3" {
		t.Errorf("expected composite-unique-test-3 for bob, got %q", gotBob.ID)
	}
}

// runIncomingInviteAcceptedIdentityCoalescedOnEmptyUpdate verifies the store
// layer (without the adapter) coalesces an empty-identity accepted update with
// the stored row so a partial write cannot erase the sender identity, and the
// raw sender FQDN is not overwritten by the empty payload.
func runIncomingInviteAcceptedIdentityCoalescedOnEmptyUpdate(t *testing.T, ctx context.Context, s store.IncomingInviteStore) {
	t.Helper()

	invite := NewIncomingInviteFixture()
	invite.ID = "store-in-coalesce-id"
	invite.Token = "store-in-coalesce-token"
	invite.RecipientUserID = "store-recipient-coalesce"
	invite.Status = fixtureStatusPending
	invite.SenderUserID = ""
	invite.SenderFQDNNormalized = ""

	createIncomingInvite(t, ctx, s, invite)

	if err := s.UpdateIncomingInviteStatusForRecipient(ctx, invite.ID, invite.RecipientUserID, fixtureStatusAccepted, "store-sender", invite.SenderFQDN); err != nil {
		t.Fatalf("UpdateIncomingInviteStatusForRecipient accepted with identity: %v", err)
	}

	// Re-accept with empty identity: the store must coalesce from the stored
	// row, not erase the sender identity.
	if err := s.UpdateIncomingInviteStatusForRecipient(ctx, invite.ID, invite.RecipientUserID, fixtureStatusAccepted, "", ""); err != nil {
		t.Fatalf("UpdateIncomingInviteStatusForRecipient accepted with empty identity: %v", err)
	}

	got, err := s.GetIncomingInviteForRecipient(ctx, invite.ID, invite.RecipientUserID)
	if err != nil {
		t.Fatalf("GetIncomingInviteForRecipient after empty update: %v", err)
	}

	if got.Status != fixtureStatusAccepted {
		t.Errorf("Status after empty update: got %q, want accepted", got.Status)
	}

	if got.SenderUserID != "store-sender" {
		t.Errorf("SenderUserID after empty update: got %q, want store-sender (coalesced from stored)", got.SenderUserID)
	}

	if got.SenderFQDNNormalized != invite.SenderFQDN {
		t.Errorf("SenderFQDNNormalized after empty update: got %q, want %q (coalesced from stored)", got.SenderFQDNNormalized, invite.SenderFQDN)
	}

	if got.SenderFQDN != invite.SenderFQDN {
		t.Errorf("SenderFQDN after empty update: got %q, want %q (raw FQDN not written back from empty payload)", got.SenderFQDN, invite.SenderFQDN)
	}
}
