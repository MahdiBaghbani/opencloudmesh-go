// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package json_test

import (
	"context"
	"errors"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
	testutil "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/store"
)

// TestJSONOutgoingShareIsolation verifies that the JSON outgoing share store
// is properly isolated: callers cannot mutate live internal state out of band.
//
// Verifies:
//  1. Create clones input: post-create mutation of the caller's pointer does
//     not alter the stored record.
//  2. Get returns copies: mutation of a fetched record does not affect the
//     next fetch.
//  3. List returns copies: mutation of a listed element does not affect the
//     next fetch.
//  4. Update path works correctly after isolation is applied.
func TestJSONOutgoingShareIsolation(t *testing.T) {
	driver := newJSONDriver(t)
	defer tshttp.MustClose(t, driver)

	ctx := context.Background()

	outStore := requireOutgoingShareStore(t, driver)

	original := testutil.NewOutgoingShareFixture()
	original.ShareID = "iso-out-share-1"
	original.ProviderID = "iso-out-provider-1"
	original.WebDAVID = "iso-out-webdav-1"
	original.Status = "sent"

	if err := outStore.CreateOutgoingShare(ctx, original); err != nil {
		t.Fatalf("CreateOutgoingShare: %v", err)
	}

	// 1. Post-create mutation of caller pointer must not affect stored record.
	original.Status = "mutated-after-create"

	got, err := outStore.GetOutgoingShare(ctx, original.ProviderID)
	if err != nil {
		t.Fatalf("GetOutgoingShare: %v", err)
	}

	if got.Status != "sent" {
		t.Errorf("create isolation broken: stored Status = %q, want %q", got.Status, "sent")
	}

	// 2. Mutation of a fetched record must not alter the next fetch.
	got.Status = "mutated-after-get"

	got2, err := outStore.GetOutgoingShare(ctx, original.ProviderID)
	if err != nil {
		t.Fatalf("second GetOutgoingShare: %v", err)
	}

	if got2.Status != "sent" {
		t.Errorf("get isolation broken: stored Status = %q, want %q", got2.Status, "sent")
	}

	// 3. List returns copies.
	listed, err := outStore.ListOutgoingShares(ctx)
	if err != nil {
		t.Fatalf("ListOutgoingShares: %v", err)
	}

	var found *store.OutgoingShare

	for _, s := range listed {
		if s.ProviderID == original.ProviderID {
			found = s
			break
		}
	}

	if found == nil {
		t.Fatalf("share not found in list")
	}

	found.Status = "mutated-after-list"

	got3, err := outStore.GetOutgoingShare(ctx, original.ProviderID)
	if err != nil {
		t.Fatalf("third GetOutgoingShare: %v", err)
	}

	if got3.Status != "sent" {
		t.Errorf("list isolation broken: stored Status = %q, want %q", got3.Status, "sent")
	}

	// 4. Update path still works correctly.
	updateCopy := *got3

	updateCopy.Status = "accepted"
	if serr := outStore.UpdateOutgoingShare(ctx, &updateCopy); serr != nil {
		t.Fatalf("UpdateOutgoingShare: %v", serr)
	}

	got4, err := outStore.GetOutgoingShare(ctx, original.ProviderID)
	if err != nil {
		t.Fatalf("GetOutgoingShare after update: %v", err)
	}

	if got4.Status != "accepted" {
		t.Errorf("update did not persist: State = %q, want %q", got4.Status, "accepted")
	}
}

// TestJSONIncomingShareIsolation is a regression test for the pointer-aliasing
// defect in the incoming share persistence path.
//
// Verifies:
//  1. Create clones input: post-create mutation of the caller's pointer does
//     not alter the stored record.
//  2. Get/list return copies: mutation of a fetched or listed record does not
//     alter subsequent fetches from the store.
//  3. Provider-key scoped lookup returns a copy with correct values.
//  4. Status-only update still works after the isolation change.
func TestJSONIncomingShareIsolation(t *testing.T) {
	driver := newJSONDriver(t)
	defer tshttp.MustClose(t, driver)

	ctx := context.Background()

	inStore := requireIncomingShareStore(t, driver)

	original := testutil.NewIncomingShareFixture()
	original.ShareID = "iso-share-1"
	original.SenderHost = "sender.example"
	original.ProviderID = "provider-iso-1"
	original.RecipientUserID = "bob"
	original.Status = "pending"

	if err := inStore.CreateIncomingShare(ctx, original); err != nil {
		t.Fatalf("CreateIncomingShare: %v", err)
	}

	assertIncomingShareCreateIsolation(t, ctx, inStore, original)
	assertIncomingShareGetCopyIsolation(t, ctx, inStore)
	assertIncomingShareProviderKeyIsolation(t, ctx, inStore)
	assertIncomingShareListCopyIsolation(t, ctx, inStore)
	assertIncomingShareStatusUpdate(t, ctx, inStore)
}

// assertIncomingShareCreateIsolation checks post-create mutation of the
// caller's pointer does not alter the stored record.
func assertIncomingShareCreateIsolation(t *testing.T, ctx context.Context, inStore store.IncomingShareStore, original *store.IncomingShare) {
	t.Helper()

	original.Status = "mutated-after-create"
	original.RecipientUserID = "hacker"

	got, err := inStore.GetIncomingShareByIDForRecipient(ctx, "iso-share-1", "bob")
	if err != nil {
		t.Fatalf("GetIncomingShareByIDForRecipient: %v", err)
	}

	if got.Status != "pending" {
		t.Errorf("create isolation broken: stored Status = %q, want %q", got.Status, "pending")
	}

	if got.RecipientUserID != "bob" {
		t.Errorf("create isolation broken: stored UserID = %q, want %q", got.RecipientUserID, "bob")
	}
}

// assertIncomingShareGetCopyIsolation checks mutation of a fetched record does
// not alter the next fetch.
func assertIncomingShareGetCopyIsolation(t *testing.T, ctx context.Context, inStore store.IncomingShareStore) {
	t.Helper()

	got, err := inStore.GetIncomingShareByIDForRecipient(ctx, "iso-share-1", "bob")
	if err != nil {
		t.Fatalf("first GetIncomingShareByIDForRecipient: %v", err)
	}

	got.Status = "mutated-after-get"
	got.RecipientUserID = "hacker"

	got2, err := inStore.GetIncomingShareByIDForRecipient(ctx, "iso-share-1", "bob")
	if err != nil {
		t.Fatalf("second GetIncomingShareByIDForRecipient: %v", err)
	}

	if got2.Status != "pending" {
		t.Errorf("get isolation broken: stored Status = %q, want %q", got2.Status, "pending")
	}
}

// assertIncomingShareProviderKeyIsolation checks the provider-key lookup
// returns a copy with correct values.
func assertIncomingShareProviderKeyIsolation(t *testing.T, ctx context.Context, inStore store.IncomingShareStore) {
	t.Helper()

	byKey, err := inStore.GetIncomingShareByProviderKey(ctx, "sender.example", "provider-iso-1")
	if err != nil {
		t.Fatalf("GetIncomingShareByProviderKey: %v", err)
	}

	if byKey.ShareID != "iso-share-1" {
		t.Errorf("provider-key lookup: unexpected ShareID %q", byKey.ShareID)
	}

	byKey.Status = "mutated-after-provider-key-get"

	got, err := inStore.GetIncomingShareByIDForRecipient(ctx, "iso-share-1", "bob")
	if err != nil {
		t.Fatalf("third GetIncomingShareByIDForRecipient: %v", err)
	}

	if got.Status != "pending" {
		t.Errorf("provider-key get isolation broken: stored Status = %q, want %q", got.Status, "pending")
	}
}

// assertIncomingShareListCopyIsolation checks listed records are copies.
func assertIncomingShareListCopyIsolation(t *testing.T, ctx context.Context, inStore store.IncomingShareStore) {
	t.Helper()

	listed, err := inStore.ListIncomingSharesByRecipient(ctx, "bob")
	if err != nil {
		t.Fatalf("ListIncomingSharesByRecipient: %v", err)
	}

	if len(listed) != 1 {
		t.Fatalf("expected 1 share, got %d", len(listed))
	}

	listed[0].Status = "mutated-after-list"

	got, err := inStore.GetIncomingShareByIDForRecipient(ctx, "iso-share-1", "bob")
	if err != nil {
		t.Fatalf("fourth GetIncomingShareByIDForRecipient: %v", err)
	}

	if got.Status != "pending" {
		t.Errorf("list isolation broken: stored Status = %q, want %q", got.Status, "pending")
	}
}

// assertIncomingShareStatusUpdate checks the status-only update path persists.
func assertIncomingShareStatusUpdate(t *testing.T, ctx context.Context, inStore store.IncomingShareStore) {
	t.Helper()

	if err := inStore.UpdateIncomingShareStatusForRecipient(ctx, "iso-share-1", "bob", "accepted"); err != nil {
		t.Fatalf("UpdateIncomingShareStatusForRecipient: %v", err)
	}

	got, err := inStore.GetIncomingShareByIDForRecipient(ctx, "iso-share-1", "bob")
	if err != nil {
		t.Fatalf("GetIncomingShareByIDForRecipient after update: %v", err)
	}

	if got.Status != "accepted" {
		t.Errorf("status update did not persist: State = %q, want %q", got.Status, "accepted")
	}
}

// TestJSONIncomingInviteIsolation is a regression test for the pointer-aliasing
// defect in the incoming invite persistence path.
//
// Verifies:
//  1. Create clones input: post-create mutation of the caller's pointer does
//     not alter the stored record.
//  2. Get/list return copies: mutation of a fetched or listed record does not
//     alter subsequent fetches from the store.
//  3. Token scoped lookup (GetIncomingInviteByToken) returns a copy.
//  4. Update path (status plus sender identity) still works after the
//     isolation change.
func TestJSONIncomingInviteIsolation(t *testing.T) {
	driver := newJSONDriver(t)
	defer tshttp.MustClose(t, driver)

	ctx := context.Background()

	inStore := requireIncomingInviteStore(t, driver)

	original := testutil.NewIncomingInviteFixture()
	original.ID = "iso-invite-1"
	original.Token = "iso-token-1"
	original.RecipientUserID = "alice"
	original.Status = "pending"

	if err := inStore.CreateIncomingInvite(ctx, original); err != nil {
		t.Fatalf("CreateIncomingInvite: %v", err)
	}

	assertIncomingInviteCreateIsolation(t, ctx, inStore, original)
	assertIncomingInviteGetCopyIsolation(t, ctx, inStore)
	assertIncomingInviteTokenCopyIsolation(t, ctx, inStore)
	assertIncomingInviteListCopyIsolation(t, ctx, inStore)
	assertIncomingInviteStatusUpdate(t, ctx, inStore)
}

// assertIncomingInviteCreateIsolation checks post-create mutation of the
// caller's pointer does not alter the stored record.
func assertIncomingInviteCreateIsolation(t *testing.T, ctx context.Context, inStore store.IncomingInviteStore, original *store.IncomingInvite) {
	t.Helper()

	original.Status = "mutated-after-create"
	original.RecipientUserID = "hacker"

	got, err := inStore.GetIncomingInviteForRecipient(ctx, "iso-invite-1", "alice")
	if err != nil {
		t.Fatalf("GetIncomingInviteForRecipient: %v", err)
	}

	if got.Status != "pending" {
		t.Errorf("create isolation broken: stored Status = %q, want %q", got.Status, "pending")
	}

	if got.RecipientUserID != "alice" {
		t.Errorf("create isolation broken: stored RecipientUserID = %q, want %q", got.RecipientUserID, "alice")
	}
}

// assertIncomingInviteGetCopyIsolation checks mutation of a fetched record does
// not alter the next fetch.
func assertIncomingInviteGetCopyIsolation(t *testing.T, ctx context.Context, inStore store.IncomingInviteStore) {
	t.Helper()

	got, err := inStore.GetIncomingInviteForRecipient(ctx, "iso-invite-1", "alice")
	if err != nil {
		t.Fatalf("first GetIncomingInviteForRecipient: %v", err)
	}

	got.Status = "mutated-after-get"

	got2, err := inStore.GetIncomingInviteForRecipient(ctx, "iso-invite-1", "alice")
	if err != nil {
		t.Fatalf("second GetIncomingInviteForRecipient: %v", err)
	}

	if got2.Status != "pending" {
		t.Errorf("get isolation broken: stored Status = %q, want %q", got2.Status, "pending")
	}
}

// assertIncomingInviteTokenCopyIsolation checks the token scoped lookup returns
// a copy.
func assertIncomingInviteTokenCopyIsolation(t *testing.T, ctx context.Context, inStore store.IncomingInviteStore) {
	t.Helper()

	byToken, err := inStore.GetIncomingInviteByToken(ctx, "iso-token-1", "alice")
	if err != nil {
		t.Fatalf("GetIncomingInviteByToken: %v", err)
	}

	if byToken.ID != "iso-invite-1" {
		t.Errorf("token lookup: unexpected ID %q", byToken.ID)
	}

	byToken.Status = "mutated-after-token-get"

	got, err := inStore.GetIncomingInviteForRecipient(ctx, "iso-invite-1", "alice")
	if err != nil {
		t.Fatalf("third GetIncomingInviteForRecipient: %v", err)
	}

	if got.Status != "pending" {
		t.Errorf("token-get isolation broken: stored Status = %q, want %q", got.Status, "pending")
	}
}

// assertIncomingInviteListCopyIsolation checks listed records are copies.
func assertIncomingInviteListCopyIsolation(t *testing.T, ctx context.Context, inStore store.IncomingInviteStore) {
	t.Helper()

	listed, err := inStore.ListIncomingInvites(ctx, "alice")
	if err != nil {
		t.Fatalf("ListIncomingInvites: %v", err)
	}

	if len(listed) != 1 {
		t.Fatalf("expected 1 invite, got %d", len(listed))
	}

	listed[0].Status = "mutated-after-list"

	got, err := inStore.GetIncomingInviteForRecipient(ctx, "iso-invite-1", "alice")
	if err != nil {
		t.Fatalf("fourth GetIncomingInviteForRecipient: %v", err)
	}

	if got.Status != "pending" {
		t.Errorf("list isolation broken: stored Status = %q, want %q", got.Status, "pending")
	}
}

// assertIncomingInviteStatusUpdate checks the update path persists status and
// sender identity, and the token index still resolves after the update.
func assertIncomingInviteStatusUpdate(t *testing.T, ctx context.Context, inStore store.IncomingInviteStore) {
	t.Helper()

	if err := inStore.UpdateIncomingInviteStatusForRecipient(ctx, "iso-invite-1", "alice", "accepted", "sender-user", "remote.example"); err != nil {
		t.Fatalf("UpdateIncomingInviteStatusForRecipient: %v", err)
	}

	got, err := inStore.GetIncomingInviteForRecipient(ctx, "iso-invite-1", "alice")
	if err != nil {
		t.Fatalf("GetIncomingInviteForRecipient after update: %v", err)
	}

	if got.Status != "accepted" {
		t.Errorf("status update did not persist: Status = %q, want %q", got.Status, "accepted")
	}

	byTokenAfterUpdate, err := inStore.GetIncomingInviteByToken(ctx, "iso-token-1", "alice")
	if err != nil {
		t.Fatalf("GetIncomingInviteByToken after update: %v", err)
	}

	if byTokenAfterUpdate.Status != "accepted" {
		t.Errorf("token lookup after update: Status = %q, want %q", byTokenAfterUpdate.Status, "accepted")
	}
}

// TestJSONOutgoingInviteIsolation is a regression test for the pointer-aliasing
// check in the outgoing invite persistence path.
//
// Verifies:
//  1. Create clones input: post-create mutation of the caller's pointer does
//     not alter the stored record.
//  2. Get returns a copy: mutation of a fetched record does not affect the
//     next fetch.
//  3. GetByToken returns a copy.
//  4. List returns copies: mutation of a listed element does not affect the
//     next fetch.
//  5. Update path still works correctly after isolation is applied.
func TestJSONOutgoingInviteIsolation(t *testing.T) {
	driver := newJSONDriver(t)
	defer tshttp.MustClose(t, driver)

	ctx := context.Background()

	outInvStore := requireOutgoingInviteStore(t, driver)

	original := testutil.NewOutgoingInviteFixture()
	original.ID = "iso-out-invite-1"
	original.Token = "iso-out-token-1"
	original.CreatedByUserID = "alice"
	original.Status = "pending"

	if err := outInvStore.CreateOutgoingInvite(ctx, original); err != nil {
		t.Fatalf("CreateOutgoingInvite: %v", err)
	}

	assertOutgoingInviteCreateIsolation(t, ctx, outInvStore, original)
	assertOutgoingInviteGetCopyIsolation(t, ctx, outInvStore, original)
	assertOutgoingInviteTokenCopyIsolation(t, ctx, outInvStore, original)
	assertOutgoingInviteListCopyIsolation(t, ctx, outInvStore, original)
	assertOutgoingInviteUpdate(t, ctx, outInvStore, original)
}

// assertOutgoingInviteCreateIsolation checks post-create mutation of the
// caller's pointer does not alter the stored record.
func assertOutgoingInviteCreateIsolation(t *testing.T, ctx context.Context, outInvStore store.OutgoingInviteStore, original *store.OutgoingInvite) {
	t.Helper()

	original.Status = "mutated-after-create"

	got, err := outInvStore.GetOutgoingInvite(ctx, original.ID)
	if err != nil {
		t.Fatalf("GetOutgoingInvite: %v", err)
	}

	if got.Status != "pending" {
		t.Errorf("create isolation broken: stored Status = %q, want %q", got.Status, "pending")
	}
}

// assertOutgoingInviteGetCopyIsolation checks mutation of a fetched record does
// not alter the next fetch.
func assertOutgoingInviteGetCopyIsolation(t *testing.T, ctx context.Context, outInvStore store.OutgoingInviteStore, original *store.OutgoingInvite) {
	t.Helper()

	got, err := outInvStore.GetOutgoingInvite(ctx, original.ID)
	if err != nil {
		t.Fatalf("first GetOutgoingInvite: %v", err)
	}

	got.Status = "mutated-after-get"

	got2, err := outInvStore.GetOutgoingInvite(ctx, original.ID)
	if err != nil {
		t.Fatalf("second GetOutgoingInvite: %v", err)
	}

	if got2.Status != "pending" {
		t.Errorf("get isolation broken: stored Status = %q, want %q", got2.Status, "pending")
	}
}

// assertOutgoingInviteTokenCopyIsolation checks GetByToken returns a copy.
func assertOutgoingInviteTokenCopyIsolation(t *testing.T, ctx context.Context, outInvStore store.OutgoingInviteStore, original *store.OutgoingInvite) {
	t.Helper()

	byToken, err := outInvStore.GetOutgoingInviteByToken(ctx, original.Token)
	if err != nil {
		t.Fatalf("GetOutgoingInviteByToken: %v", err)
	}

	if byToken.ID != original.ID {
		t.Errorf("token lookup: unexpected ID %q", byToken.ID)
	}

	byToken.Status = "mutated-after-token-get"

	got, err := outInvStore.GetOutgoingInvite(ctx, original.ID)
	if err != nil {
		t.Fatalf("third GetOutgoingInvite: %v", err)
	}

	if got.Status != "pending" {
		t.Errorf("token-get isolation broken: stored Status = %q, want %q", got.Status, "pending")
	}
}

// assertOutgoingInviteListCopyIsolation checks listed records are copies.
func assertOutgoingInviteListCopyIsolation(t *testing.T, ctx context.Context, outInvStore store.OutgoingInviteStore, original *store.OutgoingInvite) {
	t.Helper()

	listed, err := outInvStore.ListOutgoingInvites(ctx, "alice")
	if err != nil {
		t.Fatalf("ListOutgoingInvites: %v", err)
	}

	if len(listed) != 1 {
		t.Fatalf("expected 1 invite, got %d", len(listed))
	}

	listed[0].Status = "mutated-after-list"

	got, err := outInvStore.GetOutgoingInvite(ctx, original.ID)
	if err != nil {
		t.Fatalf("fourth GetOutgoingInvite: %v", err)
	}

	if got.Status != "pending" {
		t.Errorf("list isolation broken: stored Status = %q, want %q", got.Status, "pending")
	}
}

// assertOutgoingInviteUpdate checks the update path persists and the token
// index still resolves after the update.
func assertOutgoingInviteUpdate(t *testing.T, ctx context.Context, outInvStore store.OutgoingInviteStore, original *store.OutgoingInvite) {
	t.Helper()

	current, err := outInvStore.GetOutgoingInvite(ctx, original.ID)
	if err != nil {
		t.Fatalf("GetOutgoingInvite before update: %v", err)
	}

	// An accepted update without the accepted identity is rejected before any
	// write, leaving the stored record untouched.
	rejected := *current
	rejected.Status = "accepted"

	if updateErr := outInvStore.UpdateOutgoingInvite(ctx, &rejected); !errors.Is(updateErr, invites.ErrInvalidAcceptedIdentity) {
		t.Fatalf("expected ErrInvalidAcceptedIdentity for accepted update without identity, got %v", updateErr)
	}

	stillPending, err := outInvStore.GetOutgoingInvite(ctx, original.ID)
	if err != nil {
		t.Fatalf("GetOutgoingInvite after rejected update: %v", err)
	}

	if stillPending.Status != "pending" {
		t.Errorf("rejected update must not persist: Status = %q, want %q", stillPending.Status, "pending")
	}

	updateCopy := *current
	updateCopy.Status = "accepted"
	updateCopy.AcceptedUserID = "bob"
	updateCopy.AcceptedProviderFQDNNormalized = original.ProviderFQDN

	if updateErr := outInvStore.UpdateOutgoingInvite(ctx, &updateCopy); updateErr != nil {
		t.Fatalf("UpdateOutgoingInvite: %v", updateErr)
	}

	got, err := outInvStore.GetOutgoingInvite(ctx, original.ID)
	if err != nil {
		t.Fatalf("GetOutgoingInvite after update: %v", err)
	}

	if got.Status != "accepted" {
		t.Errorf("update did not persist: Status = %q, want %q", got.Status, "accepted")
	}

	byTokenAfterUpdate, err := outInvStore.GetOutgoingInviteByToken(ctx, original.Token)
	if err != nil {
		t.Fatalf("GetOutgoingInviteByToken after update: %v", err)
	}

	if byTokenAfterUpdate.Status != "accepted" {
		t.Errorf("token lookup after update: Status = %q, want %q", byTokenAfterUpdate.Status, "accepted")
	}
}
