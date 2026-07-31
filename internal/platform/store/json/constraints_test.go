// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package json_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
	testutil "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/store"
)

func TestJSONIncomingInviteRecipientScope(t *testing.T) {
	tempDir := testutil.TempDataDir(t, "ocm-test-json-incoming-invite-*")

	ctx := context.Background()
	cfg := &store.DriverConfig{
		Driver:  "json",
		DataDir: tempDir,
	}

	driver := testutil.OpenDriver(t, cfg)
	defer tshttp.MustClose(t, driver)

	inStore, ok := driver.(store.IncomingInviteStore)
	if !ok {
		t.Fatal("json driver does not implement IncomingInviteStore")
	}

	invite := &store.IncomingInvite{
		ID:              "incoming-invite-1",
		Token:           "invite-token-1",
		InviteString:    "ocm://invite",
		SenderFQDN:      "remote.example",
		RecipientUserID: "alice",
		Status:          "pending",
		ReceivedAt:      time.Now().Unix(),
		UpdatedAt:       time.Now().Unix(),
	}

	if err := inStore.CreateIncomingInvite(ctx, invite); err != nil {
		t.Fatalf("CreateIncomingInvite failed: %v", err)
	}

	got, err := inStore.GetIncomingInviteForRecipient(ctx, invite.ID, invite.RecipientUserID)
	if err != nil {
		t.Fatalf("GetIncomingInviteForRecipient failed: %v", err)
	}

	if got.ID != invite.ID {
		t.Fatalf("expected invite %q, got %q", invite.ID, got.ID)
	}

	_, err = inStore.GetIncomingInviteForRecipient(ctx, invite.ID, "bob")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for wrong recipient lookup, got %v", err)
	}

	if serr := inStore.UpdateIncomingInviteStatusForRecipient(
		ctx, invite.ID, invite.RecipientUserID, "accepted", "", "",
	); serr != nil {
		t.Fatalf("UpdateIncomingInviteStatusForRecipient failed: %v", serr)
	}

	err = inStore.UpdateIncomingInviteStatusForRecipient(ctx, invite.ID, "bob", "accepted", "", "")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for wrong recipient update, got %v", err)
	}

	err = inStore.DeleteIncomingInviteForRecipient(ctx, invite.ID, "bob")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for wrong recipient delete, got %v", err)
	}

	if serr := inStore.DeleteIncomingInviteForRecipient(ctx, invite.ID, invite.RecipientUserID); serr != nil {
		t.Fatalf("DeleteIncomingInviteForRecipient failed: %v", serr)
	}

	_, err = inStore.GetIncomingInviteForRecipient(ctx, invite.ID, invite.RecipientUserID)
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
	}
}

// TestJSONListIncomingInvitesRecipientScope ensures ListIncomingInvites always
// uses exact recipient matching: empty or wrong recipientUserID yields no results.
func TestJSONListIncomingInvitesRecipientScope(t *testing.T) {
	driver := newJSONDriver(t)
	defer tshttp.MustClose(t, driver)

	ctx := context.Background()

	inStore := requireIncomingInviteStore(t, driver)

	invite := &store.IncomingInvite{
		ID:              "scope-test-invite",
		Token:           "scope-token",
		InviteString:    "ocm://invite",
		SenderFQDN:      "remote.example",
		RecipientUserID: "alice",
		Status:          "pending",
		ReceivedAt:      time.Now().Unix(),
		UpdatedAt:       time.Now().Unix(),
	}
	if err := inStore.CreateIncomingInvite(ctx, invite); err != nil {
		t.Fatalf("CreateIncomingInvite: %v", err)
	}

	// Correct recipient returns the invite.
	got, err := inStore.ListIncomingInvites(ctx, "alice")
	if err != nil {
		t.Fatalf("ListIncomingInvites(alice): %v", err)
	}

	if len(got) != 1 {
		t.Errorf("expected 1 invite for alice, got %d", len(got))
	}

	// Wrong recipient must return empty, not all invites.
	got, err = inStore.ListIncomingInvites(ctx, "bob")
	if err != nil {
		t.Fatalf("ListIncomingInvites(bob): %v", err)
	}

	if len(got) != 0 {
		t.Errorf("expected 0 invites for bob, got %d", len(got))
	}

	// Empty string must return empty, not all invites (wildcard rejection).
	got, err = inStore.ListIncomingInvites(ctx, "")
	if err != nil {
		t.Fatalf("ListIncomingInvites(empty): %v", err)
	}

	if len(got) != 0 {
		t.Errorf("expected 0 invites for empty recipientUserID, got %d", len(got))
	}
}

// runCreateConflictingShareCase drives one outgoing-share unique-key conflict
// case: configure sets up first and second to collide on one key, the second
// create must fail with ErrAlreadyExists, and lookup must still return the
// original record owned by provider-a.
func runCreateConflictingShareCase(
	t *testing.T,
	fieldLabel string,
	configure func(first, second *store.OutgoingShare),
	lookup func(outStore store.OutgoingShareStore, ctx context.Context) (*store.OutgoingShare, error),
) {
	t.Helper()

	driver := newJSONDriver(t)
	defer tshttp.MustClose(t, driver)

	ctx := context.Background()

	outStore := requireOutgoingShareStore(t, driver)

	first := testutil.NewOutgoingShareFixture()
	second := testutil.NewOutgoingShareFixture()
	configure(first, second)

	if err := outStore.CreateOutgoingShare(ctx, first); err != nil {
		t.Fatalf("CreateOutgoingShare(first): %v", err)
	}

	err := outStore.CreateOutgoingShare(ctx, second)
	if !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("expected ErrAlreadyExists for conflicting %s, got %v", fieldLabel, err)
	}

	got, err := lookup(outStore, ctx)
	if err != nil {
		t.Fatalf("lookup after conflict: %v", err)
	}

	if got.ProviderID != "provider-a" {
		t.Errorf("original owner overwritten: expected provider-a, got %q", got.ProviderID)
	}
}

// TestJSONOutgoingShareCreateConflictingShareID verifies that creating a second
// outgoing share with a ShareID already owned by a different record returns
// ErrAlreadyExists and leaves the original record intact.
func TestJSONOutgoingShareCreateConflictingShareID(t *testing.T) {
	runCreateConflictingShareCase(
		t,
		"ShareID",
		func(first, second *store.OutgoingShare) {
			first.ProviderID = "provider-a"
			first.ShareID = "shared-id"
			first.WebDAVID = "webdav-a"

			second.ProviderID = "provider-b"
			second.ShareID = "shared-id" // same ShareID, different owner
			second.WebDAVID = "webdav-b"
		},
		func(outStore store.OutgoingShareStore, ctx context.Context) (*store.OutgoingShare, error) {
			return outStore.GetOutgoingShareByID(ctx, "shared-id")
		},
	)
}

// runUpdateConflictingShareCase drives one outgoing-share unique-key update
// conflict case: configure sets up two non-conflicting records, steal mutates
// second to collide with first on one key, the update must fail with
// ErrAlreadyExists, and lookup must still return wantOwner's record.
func runUpdateConflictingShareCase(
	t *testing.T,
	fieldLabel string,
	configure func(first, second *store.OutgoingShare),
	steal func(second *store.OutgoingShare),
	lookup func(outStore store.OutgoingShareStore, ctx context.Context) (*store.OutgoingShare, error),
	wantOwner string,
) {
	t.Helper()

	driver := newJSONDriver(t)
	defer tshttp.MustClose(t, driver)

	ctx := context.Background()

	outStore := requireOutgoingShareStore(t, driver)

	first := testutil.NewOutgoingShareFixture()
	second := testutil.NewOutgoingShareFixture()
	configure(first, second)

	if err := outStore.CreateOutgoingShare(ctx, first); err != nil {
		t.Fatalf("CreateOutgoingShare(first): %v", err)
	}

	if err := outStore.CreateOutgoingShare(ctx, second); err != nil {
		t.Fatalf("CreateOutgoingShare(second): %v", err)
	}

	steal(second)

	err := outStore.UpdateOutgoingShare(ctx, second)
	if !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("expected ErrAlreadyExists for conflicting %s on update, got %v", fieldLabel, err)
	}

	// Original mapping must be untouched.
	got, err := lookup(outStore, ctx)
	if err != nil {
		t.Fatalf("lookup after failed update: %v", err)
	}

	if got.ProviderID != wantOwner {
		t.Errorf("original owner overwritten: expected %s, got %q", wantOwner, got.ProviderID)
	}
}

// TestJSONOutgoingShareUpdateConflictingShareID verifies that updating an
// outgoing share to a ShareID already owned by a different record returns
// ErrAlreadyExists and leaves both records intact.
func TestJSONOutgoingShareUpdateConflictingShareID(t *testing.T) {
	runUpdateConflictingShareCase(
		t,
		"ShareID",
		func(first, second *store.OutgoingShare) {
			first.ProviderID = "provider-x"
			first.ShareID = "share-x"
			first.WebDAVID = "webdav-x"
			first.SharedSecret = "secret-x"

			second.ProviderID = "provider-y"
			second.ShareID = "share-y"
			second.WebDAVID = "webdav-y"
			second.SharedSecret = "secret-y"
		},
		func(second *store.OutgoingShare) { second.ShareID = "share-x" },
		func(outStore store.OutgoingShareStore, ctx context.Context) (*store.OutgoingShare, error) {
			return outStore.GetOutgoingShareByID(ctx, "share-x")
		},
		"provider-x",
	)
}

// TestJSONOutgoingShareCreateConflictingWebDAVID verifies that creating a second
// outgoing share with a WebDAVID already owned by a different record returns
// ErrAlreadyExists and leaves the original record intact.
func TestJSONOutgoingShareCreateConflictingWebDAVID(t *testing.T) {
	runCreateConflictingShareCase(
		t,
		"WebDAVID",
		func(first, second *store.OutgoingShare) {
			first.ProviderID = "provider-a"
			first.ShareID = "share-a"
			first.WebDAVID = "shared-webdav"

			second.ProviderID = "provider-b"
			second.ShareID = "share-b"
			second.WebDAVID = "shared-webdav" // same WebDAVID, different owner
		},
		func(outStore store.OutgoingShareStore, ctx context.Context) (*store.OutgoingShare, error) {
			return outStore.GetOutgoingShareByWebDAVID(ctx, "shared-webdav")
		},
	)
}

// TestJSONOutgoingShareUpdateConflictingWebDAVID verifies that updating an
// outgoing share to a WebDAVID already owned by a different record returns
// ErrAlreadyExists and leaves both records intact.
func TestJSONOutgoingShareUpdateConflictingWebDAVID(t *testing.T) {
	runUpdateConflictingShareCase(
		t,
		"WebDAVID",
		func(first, second *store.OutgoingShare) {
			first.ProviderID = "provider-m"
			first.ShareID = "share-m"
			first.WebDAVID = "webdav-m"
			first.SharedSecret = "secret-m"

			second.ProviderID = "provider-n"
			second.ShareID = "share-n"
			second.WebDAVID = "webdav-n"
			second.SharedSecret = "secret-n"
		},
		func(second *store.OutgoingShare) { second.WebDAVID = "webdav-m" },
		func(outStore store.OutgoingShareStore, ctx context.Context) (*store.OutgoingShare, error) {
			return outStore.GetOutgoingShareByWebDAVID(ctx, "webdav-m")
		},
		"provider-m",
	)
}

// TestJSONOutgoingInviteCreateConflictingToken verifies that creating a second
// outgoing invite with a Token already owned by a different record returns
// ErrAlreadyExists and leaves the original record intact.
func TestJSONOutgoingInviteCreateConflictingToken(t *testing.T) {
	driver := newJSONDriver(t)
	defer tshttp.MustClose(t, driver)

	ctx := context.Background()

	outInvStore := requireOutgoingInviteStore(t, driver)

	first := testutil.NewOutgoingInviteFixture()
	first.ID = "invite-a"

	first.Token = "shared-token"
	if err := outInvStore.CreateOutgoingInvite(ctx, first); err != nil {
		t.Fatalf("CreateOutgoingInvite(first): %v", err)
	}

	second := testutil.NewOutgoingInviteFixture()
	second.ID = "invite-b"
	second.Token = "shared-token" // same token, different invite ID

	err := outInvStore.CreateOutgoingInvite(ctx, second)
	if !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("expected ErrAlreadyExists for conflicting Token, got %v", err)
	}

	// Original must still be reachable.
	got, err := outInvStore.GetOutgoingInviteByToken(ctx, "shared-token")
	if err != nil {
		t.Fatalf("GetOutgoingInviteByToken after conflict: %v", err)
	}

	if got.ID != "invite-a" {
		t.Errorf("original invite overwritten: expected invite-a, got %q", got.ID)
	}
}

// TestJSONOutgoingInviteUpdateConflictingToken verifies that updating an
// outgoing invite to a Token already owned by a different record returns
// ErrAlreadyExists and leaves both records intact.
func TestJSONOutgoingInviteUpdateConflictingToken(t *testing.T) {
	driver := newJSONDriver(t)
	defer tshttp.MustClose(t, driver)

	ctx := context.Background()

	outInvStore := requireOutgoingInviteStore(t, driver)

	first := testutil.NewOutgoingInviteFixture()
	first.ID = "invite-p"

	first.Token = "token-p"
	if err := outInvStore.CreateOutgoingInvite(ctx, first); err != nil {
		t.Fatalf("CreateOutgoingInvite(first): %v", err)
	}

	second := testutil.NewOutgoingInviteFixture()
	second.ID = "invite-q"

	second.Token = "token-q"
	if err := outInvStore.CreateOutgoingInvite(ctx, second); err != nil {
		t.Fatalf("CreateOutgoingInvite(second): %v", err)
	}

	// Attempt to steal first's token via update.
	second.Token = "token-p"

	err := outInvStore.UpdateOutgoingInvite(ctx, second)
	if !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("expected ErrAlreadyExists for conflicting Token on update, got %v", err)
	}

	// Original mapping must be untouched.
	got, err := outInvStore.GetOutgoingInviteByToken(ctx, "token-p")
	if err != nil {
		t.Fatalf("GetOutgoingInviteByToken after failed update: %v", err)
	}

	if got.ID != "invite-p" {
		t.Errorf("original invite overwritten: expected invite-p, got %q", got.ID)
	}
}
