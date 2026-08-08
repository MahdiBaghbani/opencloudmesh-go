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

// runOutgoingShareDuplicateSharedSecret verifies that a non-empty SharedSecret
// is unique across outgoing shares:
// - a duplicate non-empty secret on create returns ErrAlreadyExists
// - the original record is preserved by GetOutgoingShareBySharedSecret
// - attempting to steal the secret via update also returns ErrAlreadyExists
// - multiple shares with an empty secret are allowed (not subject to the constraint).
func runOutgoingShareDuplicateSharedSecret(
	t *testing.T,
	ctx context.Context,
	s store.OutgoingShareStore,
) {
	t.Helper()

	first := &store.OutgoingShare{
		ShareID:      "dup-secret-share-1",
		ProviderID:   "dup-secret-provider-1",
		WebDAVID:     "dup-secret-webdav-1",
		SharedSecret: "dup-shared-secret",
		LocalPath:    "/path/a",
		Owner:        "alice@example.com",
		Sender:       "alice@example.com",
		ShareWith:    "bob@remote.com",
		ReceiverHost: "remote.com",
		Name:         "file.txt",
		ResourceType: "file",
		Permissions:  "read",
		Status:       "sent",
		CreatedAt:    time.Now().Unix(),
		UpdatedAt:    time.Now().Unix(),
	}
	createOutgoingShare(t, ctx, s, first)

	second := &store.OutgoingShare{
		ShareID:      "dup-secret-share-2",
		ProviderID:   "dup-secret-provider-2",
		WebDAVID:     "dup-secret-webdav-2",
		SharedSecret: "dup-shared-secret",
		LocalPath:    "/path/b",
		Owner:        "alice@example.com",
		Sender:       "alice@example.com",
		ShareWith:    "bob@remote.com",
		ReceiverHost: "remote.com",
		Name:         "file.txt",
		ResourceType: "file",
		Permissions:  "read",
		Status:       "sent",
		CreatedAt:    time.Now().Unix(),
		UpdatedAt:    time.Now().Unix(),
	}
	requireDuplicateSharedSecretCreateFails(t, ctx, s, second)
	requireOutgoingShareBySharedSecretProviderID(t, ctx, s, "dup-shared-secret", "dup-secret-provider-1")

	third := &store.OutgoingShare{
		ShareID:      "dup-secret-share-3",
		ProviderID:   "dup-secret-provider-3",
		WebDAVID:     "dup-secret-webdav-3",
		SharedSecret: "different-secret",
		LocalPath:    "/path/c",
		Owner:        "alice@example.com",
		Sender:       "alice@example.com",
		ShareWith:    "bob@remote.com",
		ReceiverHost: "remote.com",
		Name:         "file.txt",
		ResourceType: "file",
		Permissions:  "read",
		Status:       "sent",
		CreatedAt:    time.Now().Unix(),
		UpdatedAt:    time.Now().Unix(),
	}
	createOutgoingShare(t, ctx, s, third)
	requireUpdateSharedSecretFails(t, ctx, s, third, "dup-shared-secret")

	noSecret1 := &store.OutgoingShare{
		ShareID:      "no-secret-share-1",
		ProviderID:   "no-secret-provider-1",
		WebDAVID:     "no-secret-webdav-1",
		SharedSecret: "",
		LocalPath:    "/path/d",
		Owner:        "alice@example.com",
		Sender:       "alice@example.com",
		ShareWith:    "bob@remote.com",
		ReceiverHost: "remote.com",
		Name:         "file.txt",
		ResourceType: "file",
		Permissions:  "read",
		Status:       "sent",
		CreatedAt:    time.Now().Unix(),
		UpdatedAt:    time.Now().Unix(),
	}
	noSecret2 := &store.OutgoingShare{
		ShareID:      "no-secret-share-2",
		ProviderID:   "no-secret-provider-2",
		WebDAVID:     "no-secret-webdav-2",
		SharedSecret: "",
		LocalPath:    "/path/e",
		Owner:        "alice@example.com",
		Sender:       "alice@example.com",
		ShareWith:    "bob@remote.com",
		ReceiverHost: "remote.com",
		Name:         "file.txt",
		ResourceType: "file",
		Permissions:  "read",
		Status:       "sent",
		CreatedAt:    time.Now().Unix(),
		UpdatedAt:    time.Now().Unix(),
	}

	createOutgoingShare(t, ctx, s, noSecret1)
	createOutgoingShare(t, ctx, s, noSecret2)
}

func requireDuplicateSharedSecretCreateFails(t *testing.T, ctx context.Context, s store.OutgoingShareStore, share *store.OutgoingShare) {
	t.Helper()

	if err := s.CreateOutgoingShare(ctx, share); !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("expected ErrAlreadyExists for duplicate SharedSecret on create, got %v", err)
	}
}

func requireOutgoingShareBySharedSecretProviderID(t *testing.T, ctx context.Context, s store.OutgoingShareStore, secret, want string) {
	t.Helper()

	got, err := s.GetOutgoingShareBySharedSecret(ctx, secret)
	if err != nil {
		t.Fatalf("GetOutgoingShareBySharedSecret after conflict: %v", err)
	}

	if got.ProviderID != want {
		t.Errorf("original share overwritten: expected %q, got %q", want, got.ProviderID)
	}
}

func requireUpdateSharedSecretFails(t *testing.T, ctx context.Context, s store.OutgoingShareStore, share *store.OutgoingShare, targetSecret string) {
	t.Helper()

	share.SharedSecret = targetSecret
	if err := s.UpdateOutgoingShare(ctx, share); !errors.Is(err, store.ErrAlreadyExists) {
		t.Errorf("expected ErrAlreadyExists for conflicting SharedSecret on update, got %v", err)
	}
}

// runOutgoingShareEmptySharedSecretLookup verifies that empty shared secret is
// not a valid lookup key across all backends:
//   - GetOutgoingShareBySharedSecret("") must return ErrNotFound even when rows
//     with an empty shared secret exist (empty is an optional field allowed on
//     multiple rows, not a singular index key).
func runOutgoingShareEmptySharedSecretLookup(
	t *testing.T,
	ctx context.Context,
	s store.OutgoingShareStore,
) {
	t.Helper()

	row := &store.OutgoingShare{
		ShareID:      "empty-secret-lookup-share-1",
		ProviderID:   "empty-secret-lookup-provider-1",
		WebDAVID:     "empty-secret-lookup-webdav-1",
		SharedSecret: "",
		LocalPath:    "/path/empty-a",
		Owner:        "alice@example.com",
		Sender:       "alice@example.com",
		ShareWith:    "bob@remote.com",
		ReceiverHost: "remote.com",
		Name:         "file.txt",
		ResourceType: "file",
		Permissions:  "read",
		Status:       "sent",
		CreatedAt:    time.Now().Unix(),
		UpdatedAt:    time.Now().Unix(),
	}
	if err := s.CreateOutgoingShare(ctx, row); err != nil {
		t.Fatalf("CreateOutgoingShare(empty-secret row): %v", err)
	}

	t.Cleanup(func() {
		if err := s.DeleteOutgoingShare(ctx, row.ProviderID); err != nil {
			t.Errorf("cleanup: DeleteOutgoingShare empty-secret row: %v", err)
		}
	})

	_, err := s.GetOutgoingShareBySharedSecret(ctx, "")
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetOutgoingShareBySharedSecret(\"\") expected ErrNotFound, got %v", err)
	}
}

// runOutgoingShareUpdateNotFound verifies that UpdateOutgoingShare returns
// ErrNotFound when the target record does not exist.
func runOutgoingShareUpdateNotFound(t *testing.T, ctx context.Context, s store.OutgoingShareStore) {
	t.Helper()

	ghost := NewOutgoingShareFixture()
	ghost.ProviderID = "update-missing-out-share-provider"
	ghost.ShareID = "update-missing-out-share-id"
	ghost.WebDAVID = "update-missing-out-share-webdav"

	if err := s.UpdateOutgoingShare(ctx, ghost); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected ErrNotFound for update of missing outgoing share, got %v", err)
	}
}
