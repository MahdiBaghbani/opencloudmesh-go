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

func runIncomingShareCRUD(t *testing.T, ctx context.Context, s store.IncomingShareStore) {
	t.Helper()

	share := NewIncomingShareFixture()
	share.UpdatedAt = time.Now().Add(-2 * time.Second).Unix()

	createIncomingShare(t, ctx, s, share)
	requireIncomingShareByIDForRecipient(t, ctx, s, share)
	requireIncomingShareNotFoundForRecipient(t, ctx, s, share.ShareID, "other-user")
	requireIncomingShareByProviderKey(t, ctx, s, share)
	updateIncomingShareStatusAndAssert(t, ctx, s, share, fixtureStatusAccepted)
	requireIncomingShareStatusUpdateNotFoundForRecipient(t, ctx, s, share.ShareID, "other-user", fixtureStatusAccepted)
	requireIncomingShareListByRecipientNonEmpty(t, ctx, s, share.RecipientUserID)
	deleteIncomingShareForRecipient(t, ctx, s, share.ShareID, share.RecipientUserID)
	requireIncomingShareNotFoundForRecipient(t, ctx, s, share.ShareID, share.RecipientUserID)
}

func createIncomingShare(t *testing.T, ctx context.Context, s store.IncomingShareStore, share *store.IncomingShare) {
	t.Helper()

	if err := s.CreateIncomingShare(ctx, share); err != nil {
		t.Fatalf("CreateIncomingShare failed: %v", err)
	}

	t.Cleanup(func() {
		if err := s.DeleteIncomingShareForRecipient(ctx, share.ShareID, share.RecipientUserID); err != nil && !errors.Is(err, store.ErrNotFound) {
			t.Errorf("cleanup: DeleteIncomingShareForRecipient: %v", err)
		}
	})
}

func requireIncomingShareByIDForRecipient(t *testing.T, ctx context.Context, s store.IncomingShareStore, want *store.IncomingShare) {
	t.Helper()

	got, err := s.GetIncomingShareByIDForRecipient(ctx, want.ShareID, want.RecipientUserID)
	if err != nil {
		t.Fatalf("GetIncomingShareByIDForRecipient failed: %v", err)
	}

	if got.ShareID != want.ShareID {
		t.Errorf("expected shareID %q, got %q", want.ShareID, got.ShareID)
	}
}

func requireIncomingShareNotFoundForRecipient(t *testing.T, ctx context.Context, s store.IncomingShareStore, shareID, userID string) {
	t.Helper()

	_, err := s.GetIncomingShareByIDForRecipient(ctx, shareID, userID)
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected ErrNotFound for wrong recipient, got %v", err)
	}
}

func requireIncomingShareByProviderKey(t *testing.T, ctx context.Context, s store.IncomingShareStore, want *store.IncomingShare) {
	t.Helper()

	got, err := s.GetIncomingShareByProviderKey(ctx, want.SenderHost, want.ProviderID)
	if err != nil {
		t.Fatalf("GetIncomingShareByProviderKey failed: %v", err)
	}

	if got.ShareID != want.ShareID {
		t.Errorf("expected shareID %q, got %q", want.ShareID, got.ShareID)
	}
}

func updateIncomingShareStatusAndAssert(t *testing.T, ctx context.Context, s store.IncomingShareStore, share *store.IncomingShare, status string) {
	t.Helper()

	priorUpdatedAt := share.UpdatedAt
	if err := s.UpdateIncomingShareStatusForRecipient(ctx, share.ShareID, share.RecipientUserID, status); err != nil {
		t.Fatalf("UpdateIncomingShareStatusForRecipient failed: %v", err)
	}

	updated, err := s.GetIncomingShareByIDForRecipient(ctx, share.ShareID, share.RecipientUserID)
	if err != nil {
		t.Fatalf("GetIncomingShareByIDForRecipient after status update failed: %v", err)
	}

	if updated.Status != status {
		t.Errorf("expected status %q after status update, got %q", status, updated.Status)
	}

	if updated.UpdatedAt <= priorUpdatedAt {
		t.Errorf(
			"UpdatedAt not increased after status update: got %d, want > %d",
			updated.UpdatedAt,
			priorUpdatedAt,
		)
	}
}

func requireIncomingShareStatusUpdateNotFoundForRecipient(
	t *testing.T,
	ctx context.Context,
	s store.IncomingShareStore,
	shareID,
	userID,
	state string,
) {
	t.Helper()

	err := s.UpdateIncomingShareStatusForRecipient(ctx, shareID, userID, state)
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected ErrNotFound for wrong recipient on update, got %v", err)
	}
}

func requireIncomingShareListByRecipientNonEmpty(t *testing.T, ctx context.Context, s store.IncomingShareStore, userID string) {
	t.Helper()

	shares, err := s.ListIncomingSharesByRecipient(ctx, userID)
	if err != nil {
		t.Fatalf("ListIncomingSharesByRecipient failed: %v", err)
	}

	if len(shares) == 0 {
		t.Error("expected at least one share in list")
	}
}

func deleteIncomingShareForRecipient(t *testing.T, ctx context.Context, s store.IncomingShareStore, shareID, userID string) {
	t.Helper()

	if err := s.DeleteIncomingShareForRecipient(ctx, shareID, userID); err != nil {
		t.Fatalf("DeleteIncomingShareForRecipient failed: %v", err)
	}
}

// runProviderKeyScopedLookup verifies sender-scoped provider key lookup.
func runProviderKeyScopedLookup(t *testing.T, ctx context.Context, s store.IncomingShareStore) {
	t.Helper()
	// Create two shares with same providerID but different senders
	share1 := NewIncomingShareFixture()
	share1.ShareID = "share-1"
	share1.SenderHost = "server1.com"
	share1.ProviderID = "same-provider-id"

	share2 := NewIncomingShareFixture()
	share2.ShareID = "share-2"
	share2.SenderHost = "server2.com"
	share2.ProviderID = "same-provider-id"

	if err := s.CreateIncomingShare(ctx, share1); err != nil {
		t.Fatalf("CreateIncomingShare share1 failed: %v", err)
	}

	t.Cleanup(func() {
		if err := s.DeleteIncomingShareForRecipient(ctx, share1.ShareID, share1.RecipientUserID); err != nil && !errors.Is(err, store.ErrNotFound) {
			t.Errorf("cleanup: DeleteIncomingShareForRecipient share1: %v", err)
		}
	})

	if err := s.CreateIncomingShare(ctx, share2); err != nil {
		t.Fatalf("CreateIncomingShare share2 failed: %v", err)
	}

	t.Cleanup(func() {
		if err := s.DeleteIncomingShareForRecipient(ctx, share2.ShareID, share2.RecipientUserID); err != nil && !errors.Is(err, store.ErrNotFound) {
			t.Errorf("cleanup: DeleteIncomingShareForRecipient share2: %v", err)
		}
	})

	// Lookup by server1 should return share1
	got, err := s.GetIncomingShareByProviderKey(ctx, "server1.com", "same-provider-id")
	if err != nil {
		t.Fatalf("GetIncomingShareByProviderKey server1 failed: %v", err)
	}

	if got.ShareID != "share-1" {
		t.Errorf("expected share-1, got %q", got.ShareID)
	}

	// Lookup by server2 should return share2
	got, err = s.GetIncomingShareByProviderKey(ctx, "server2.com", "same-provider-id")
	if err != nil {
		t.Fatalf("GetIncomingShareByProviderKey server2 failed: %v", err)
	}

	if got.ShareID != "share-2" {
		t.Errorf("expected share-2, got %q", got.ShareID)
	}
}

// runIncomingShareProviderKeyUniqueness verifies that (sendingServer, providerID)
// is enforced as a composite unique key across all backends:
// - a duplicate pair returns ErrAlreadyExists
// - the original record is still returned by GetIncomingShareByProviderKey
// - the same providerID with a different sendingServer still succeeds.
func runIncomingShareProviderKeyUniqueness(
	t *testing.T,
	ctx context.Context,
	s store.IncomingShareStore,
) {
	t.Helper()

	first := &store.IncomingShare{
		ShareID:         "provider-key-unique-1",
		SenderHost:      "provider-key-server.com",
		ProviderID:      fixtureProviderKeyUniquePID,
		Owner:           fixtureOwnerAliceSender,
		Sender:          fixtureOwnerAliceSender,
		ShareWith:       fixtureShareWithBobExample,
		Name:            fixtureNameSharedTxt,
		ResourceType:    fixtureResourceTypeFile,
		Permissions:     fixturePermissionsRead,
		Status:          fixtureStatusPending,
		RecipientUserID: fixtureUserBob,
		CreatedAt:       time.Now().Unix(),
		UpdatedAt:       time.Now().Unix(),
	}
	if err := s.CreateIncomingShare(ctx, first); err != nil {
		t.Fatalf("CreateIncomingShare(first): %v", err)
	}

	t.Cleanup(func() {
		if err := s.DeleteIncomingShareForRecipient(ctx, first.ShareID, first.RecipientUserID); err != nil && !errors.Is(err, store.ErrNotFound) {
			t.Errorf("cleanup: DeleteIncomingShareForRecipient first: %v", err)
		}
	})

	// Same (sendingServer, providerID), different shareID: must fail.
	second := &store.IncomingShare{
		ShareID:         "provider-key-unique-2",
		SenderHost:      "provider-key-server.com",
		ProviderID:      fixtureProviderKeyUniquePID,
		Owner:           fixtureOwnerAliceSender,
		Sender:          fixtureOwnerAliceSender,
		ShareWith:       fixtureShareWithBobExample,
		Name:            fixtureNameSharedTxt,
		ResourceType:    fixtureResourceTypeFile,
		Permissions:     fixturePermissionsRead,
		Status:          fixtureStatusPending,
		RecipientUserID: fixtureUserBob,
		CreatedAt:       time.Now().Unix(),
		UpdatedAt:       time.Now().Unix(),
	}
	if err := s.CreateIncomingShare(ctx, second); !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("expected ErrAlreadyExists for duplicate (sendingServer, providerID), got %v", err)
	}

	// Original must still be found by provider key lookup.
	got, err := s.GetIncomingShareByProviderKey(ctx, "provider-key-server.com", fixtureProviderKeyUniquePID)
	if err != nil {
		t.Fatalf("GetIncomingShareByProviderKey after conflict: %v", err)
	}

	if got.ShareID != "provider-key-unique-1" {
		t.Errorf(
			"original share overwritten: expected provider-key-unique-1, got %q",
			got.ShareID,
		)
	}

	// Same providerID, different sendingServer: must succeed.
	third := &store.IncomingShare{
		ShareID:         "provider-key-unique-3",
		SenderHost:      "other-server.com",
		ProviderID:      fixtureProviderKeyUniquePID,
		Owner:           fixtureOwnerAliceSender,
		Sender:          fixtureOwnerAliceSender,
		ShareWith:       fixtureShareWithBobExample,
		Name:            fixtureNameSharedTxt,
		ResourceType:    fixtureResourceTypeFile,
		Permissions:     fixturePermissionsRead,
		Status:          fixtureStatusPending,
		RecipientUserID: fixtureUserBob,
		CreatedAt:       time.Now().Unix(),
		UpdatedAt:       time.Now().Unix(),
	}
	if createErr := s.CreateIncomingShare(ctx, third); createErr != nil {
		t.Fatalf("CreateIncomingShare(third, different sendingServer): %v", createErr)
	}

	t.Cleanup(func() {
		if deleteErr := s.DeleteIncomingShareForRecipient(ctx, third.ShareID, third.RecipientUserID); deleteErr != nil && !errors.Is(deleteErr, store.ErrNotFound) {
			t.Errorf("cleanup: DeleteIncomingShareForRecipient third: %v", deleteErr)
		}
	})

	gotThird, err := s.GetIncomingShareByProviderKey(ctx, "other-server.com", fixtureProviderKeyUniquePID)
	if err != nil {
		t.Fatalf("GetIncomingShareByProviderKey for third: %v", err)
	}

	if gotThird.ShareID != "provider-key-unique-3" {
		t.Errorf("expected provider-key-unique-3, got %q", gotThird.ShareID)
	}
}
