// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// Package store provides shared test helpers for store driver tests.
package store

import (
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
)

// NewOutgoingInviteFixture creates a test outgoing invite.
func NewOutgoingInviteFixture() *store.OutgoingInvite {
	return &store.OutgoingInvite{
		ID:              "test-outgoing-invite-id",
		Token:           "test-invite-token",
		ProviderFQDN:    "example.com",
		InviteString:    fixtureInviteString,
		RecipientEmail:  fixtureShareWithBobRemote,
		CreatedByUserID: fixtureUserAlice,
		Status:          fixtureStatusPending,
		ExpiresAt:       time.Now().Add(24 * time.Hour).Unix(),
		CreatedAt:       time.Now().Unix(),
		UpdatedAt:       time.Now().Unix(),
	}
}

// NewIncomingInviteFixture creates a test incoming invite.
func NewIncomingInviteFixture() *store.IncomingInvite {
	return &store.IncomingInvite{
		ID:              "test-incoming-invite-id",
		Token:           "test-invite-token",
		InviteString:    fixtureInviteString,
		SenderFQDN:      fixtureRemoteExample,
		RecipientUserID: fixtureUserAlice,
		Status:          fixtureStatusPending,
		ReceivedAt:      time.Now().Unix(),
		UpdatedAt:       time.Now().Unix(),
	}
}

// NewOutgoingShareFixture creates a test outgoing share.
func NewOutgoingShareFixture() *store.OutgoingShare {
	return &store.OutgoingShare{
		ShareID:      "test-share-id",
		ProviderID:   "test-provider-id",
		WebDAVID:     "test-webdav-id",
		SharedSecret: "super-secret-token",
		LocalPath:    "/path/to/file.txt",
		Owner:        fixtureOwnerAliceExample,
		Sender:       fixtureOwnerAliceExample,
		ShareWith:    fixtureShareWithBobRemote,
		ReceiverHost: fixtureReceiverRemote,
		Name:         fixtureNameFileTxt,
		ResourceType: fixtureResourceTypeFile,
		Permissions:  fixturePermissionsRead,
		Status:       fixtureStatusSent,
		CreatedAt:    time.Now().Unix(),
		UpdatedAt:    time.Now().Unix(),
	}
}

// NewIncomingShareFixture creates a test incoming share.
func NewIncomingShareFixture() *store.IncomingShare {
	return &store.IncomingShare{
		ShareID:         "test-share-id",
		SenderHost:      "sender.com",
		ProviderID:      "remote-provider-id",
		WebDAVID:        "remote-webdav-id",
		SharedSecret:    "received-secret",
		Owner:           fixtureOwnerAliceSender,
		Sender:          fixtureOwnerAliceSender,
		ShareWith:       fixtureShareWithBobExample,
		Name:            "shared-file.txt",
		ResourceType:    fixtureResourceTypeFile,
		Permissions:     fixturePermissionsRead,
		Status:          fixtureStatusPending,
		RecipientUserID: fixtureUserBob,
		CreatedAt:       time.Now().Unix(),
		UpdatedAt:       time.Now().Unix(),
	}
}
