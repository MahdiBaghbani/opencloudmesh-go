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
		InviteString:    "ocm://invite/test",
		RecipientEmail:  "bob@remote.com",
		CreatedByUserID: "alice",
		Status:          "pending",
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
		InviteString:    "ocm://invite/test",
		SenderFQDN:      "remote.example",
		RecipientUserID: "alice",
		Status:          "pending",
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
}

// NewIncomingShareFixture creates a test incoming share.
func NewIncomingShareFixture() *store.IncomingShare {
	return &store.IncomingShare{
		ShareID:         "test-share-id",
		SenderHost:      "sender.com",
		ProviderID:      "remote-provider-id",
		WebDAVID:        "remote-webdav-id",
		SharedSecret:    "received-secret",
		Owner:           "alice@sender.com",
		Sender:          "alice@sender.com",
		ShareWith:       "bob@example.com",
		Name:            "shared-file.txt",
		ResourceType:    "file",
		Permissions:     "read",
		Status:          "pending",
		RecipientUserID: "bob",
		CreatedAt:       time.Now().Unix(),
		UpdatedAt:       time.Now().Unix(),
	}
}
