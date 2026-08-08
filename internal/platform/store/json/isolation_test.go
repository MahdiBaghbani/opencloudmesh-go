// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package json_test

import (
	"context"
	"testing"

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
