// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package outgoing_test

import (
	"context"
	"testing"

	tsrepos "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/repos"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
)

func TestOutgoingShareRepo_CreateAndLookup(t *testing.T) {
	t.Parallel()
	repo := tsrepos.OpenMemory(t).OutgoingShares
	ctx := context.Background()

	share := &outgoing.OutgoingShare{
		ProviderID:   "provider-123",
		WebDAVID:     "webdav-456",
		SharedSecret: "secret",
		LocalPath:    "/tmp/test.txt",
		ReceiverHost: "receiver.example.com",
		ShareWith:    "user@receiver.example.com",
		Name:         "test.txt",
		ResourceType: "file",
		ShareType:    "user",
		Permissions:  []string{"read"},
		Status:       "sent",
	}

	if err := repo.Create(ctx, share); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Lookup by shareID
	found, err := repo.GetByID(ctx, share.ShareID)
	if err != nil {
		t.Fatalf("GetByID failed: %v", err)
	}

	if found.ProviderID != share.ProviderID {
		t.Error("wrong providerID")
	}

	// Lookup by providerID
	found, err = repo.GetByProviderID(ctx, "provider-123")
	if err != nil {
		t.Fatalf("GetByProviderID failed: %v", err)
	}

	if found.ShareID != share.ShareID {
		t.Error("wrong shareID from providerID lookup")
	}

	// Lookup by webdavID
	found, err = repo.GetByWebDAVID(ctx, "webdav-456")
	if err != nil {
		t.Fatalf("GetByWebDAVID failed: %v", err)
	}

	if found.ShareID != share.ShareID {
		t.Error("wrong shareID from webdavID lookup")
	}
}
