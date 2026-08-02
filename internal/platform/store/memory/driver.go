// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// Package memory implements an in-memory persistence driver.
// It is a thin wrapper over the shared memcore.Core engine; nothing touches disk.
package memory

import (
	"context"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/memcore"
)

func init() {
	store.Register("memory", NewDriver)
}

// Driver implements the store.Driver interface using the shared in-memory core.
// It implements all four persistence surfaces: OutgoingShareStore,
// IncomingShareStore, OutgoingInviteStore, and IncomingInviteStore.
type Driver struct {
	core *memcore.Core
}

// NewDriver creates a new memory driver instance. DataDir is ignored.
func NewDriver(_ *store.DriverConfig) (store.Driver, error) {
	return &Driver{}, nil
}

// Name returns the driver name.
func (d *Driver) Name() string {
	return "memory"
}

// Init allocates the in-memory core; there is nothing to load.
func (d *Driver) Init(_ context.Context) error {
	d.core = memcore.NewCore()

	return nil
}

// Close marks the core closed. Safe to call before Init.
func (d *Driver) Close() error {
	return d.core.Close()
}

// CreateOutgoingShare creates a new outgoing share.
func (d *Driver) CreateOutgoingShare(ctx context.Context, share *store.OutgoingShare) error {
	return d.core.CreateOutgoingShare(ctx, share)
}

// GetOutgoingShareByID retrieves an outgoing share by its local share id.
func (d *Driver) GetOutgoingShareByID(ctx context.Context, shareID string) (*store.OutgoingShare, error) {
	return d.core.GetOutgoingShareByID(ctx, shareID)
}

// GetOutgoingShare retrieves an outgoing share by provider id.
func (d *Driver) GetOutgoingShare(ctx context.Context, providerID string) (*store.OutgoingShare, error) {
	return d.core.GetOutgoingShare(ctx, providerID)
}

// GetOutgoingShareByWebDAVID retrieves an outgoing share by webdav id.
func (d *Driver) GetOutgoingShareByWebDAVID(ctx context.Context, webdavID string) (*store.OutgoingShare, error) {
	return d.core.GetOutgoingShareByWebDAVID(ctx, webdavID)
}

// GetOutgoingShareBySharedSecret retrieves an outgoing share by shared secret.
func (d *Driver) GetOutgoingShareBySharedSecret(ctx context.Context, sharedSecret string) (*store.OutgoingShare, error) {
	return d.core.GetOutgoingShareBySharedSecret(ctx, sharedSecret)
}

// UpdateOutgoingShare updates an existing outgoing share.
func (d *Driver) UpdateOutgoingShare(ctx context.Context, share *store.OutgoingShare) error {
	return d.core.UpdateOutgoingShare(ctx, share)
}

// DeleteOutgoingShare deletes an outgoing share by provider id.
func (d *Driver) DeleteOutgoingShare(ctx context.Context, providerID string) error {
	return d.core.DeleteOutgoingShare(ctx, providerID)
}

// ListOutgoingShares returns all outgoing shares.
func (d *Driver) ListOutgoingShares(ctx context.Context) ([]*store.OutgoingShare, error) {
	return d.core.ListOutgoingShares(ctx)
}

// CreateIncomingShare creates a new incoming share.
func (d *Driver) CreateIncomingShare(ctx context.Context, share *store.IncomingShare) error {
	return d.core.CreateIncomingShare(ctx, share)
}

// GetIncomingShareByIDForRecipient retrieves an incoming share by share id scoped to a recipient.
func (d *Driver) GetIncomingShareByIDForRecipient(ctx context.Context, shareID string, recipientUserID string) (*store.IncomingShare, error) {
	return d.core.GetIncomingShareByIDForRecipient(ctx, shareID, recipientUserID)
}

// GetIncomingShareByProviderKey retrieves an incoming share by sending server and provider id.
func (d *Driver) GetIncomingShareByProviderKey(ctx context.Context, sendingServer, providerID string) (*store.IncomingShare, error) {
	return d.core.GetIncomingShareByProviderKey(ctx, sendingServer, providerID)
}

// ListIncomingSharesByRecipient returns incoming shares for the given recipient user.
func (d *Driver) ListIncomingSharesByRecipient(ctx context.Context, recipientUserID string) ([]*store.IncomingShare, error) {
	return d.core.ListIncomingSharesByRecipient(ctx, recipientUserID)
}

// UpdateIncomingShareStatusForRecipient updates the status of an incoming share scoped to a recipient.
func (d *Driver) UpdateIncomingShareStatusForRecipient(ctx context.Context, shareID string, recipientUserID string, status string) error {
	return d.core.UpdateIncomingShareStatusForRecipient(ctx, shareID, recipientUserID, status)
}

// DeleteIncomingShareForRecipient deletes an incoming share scoped to a recipient.
func (d *Driver) DeleteIncomingShareForRecipient(ctx context.Context, shareID string, recipientUserID string) error {
	return d.core.DeleteIncomingShareForRecipient(ctx, shareID, recipientUserID)
}

// CreateOutgoingInvite creates a new outgoing invite.
func (d *Driver) CreateOutgoingInvite(ctx context.Context, invite *store.OutgoingInvite) error {
	return d.core.CreateOutgoingInvite(ctx, invite)
}

// GetOutgoingInvite retrieves an outgoing invite by id.
func (d *Driver) GetOutgoingInvite(ctx context.Context, id string) (*store.OutgoingInvite, error) {
	return d.core.GetOutgoingInvite(ctx, id)
}

// GetOutgoingInviteByToken retrieves an outgoing invite by token.
func (d *Driver) GetOutgoingInviteByToken(ctx context.Context, token string) (*store.OutgoingInvite, error) {
	return d.core.GetOutgoingInviteByToken(ctx, token)
}

// UpdateOutgoingInvite updates an existing outgoing invite.
func (d *Driver) UpdateOutgoingInvite(ctx context.Context, invite *store.OutgoingInvite) error {
	return d.core.UpdateOutgoingInvite(ctx, invite)
}

// DeleteOutgoingInvite deletes an outgoing invite by id.
func (d *Driver) DeleteOutgoingInvite(ctx context.Context, id string) error {
	return d.core.DeleteOutgoingInvite(ctx, id)
}

// ListOutgoingInvites returns outgoing invites for a user. An empty userID lists all invites.
func (d *Driver) ListOutgoingInvites(ctx context.Context, userID string) ([]*store.OutgoingInvite, error) {
	return d.core.ListOutgoingInvites(ctx, userID)
}

// CreateIncomingInvite creates a new incoming invite.
func (d *Driver) CreateIncomingInvite(ctx context.Context, invite *store.IncomingInvite) error {
	return d.core.CreateIncomingInvite(ctx, invite)
}

// GetIncomingInviteForRecipient retrieves an incoming invite by id scoped to a recipient.
func (d *Driver) GetIncomingInviteForRecipient(ctx context.Context, id string, recipientUserID string) (*store.IncomingInvite, error) {
	return d.core.GetIncomingInviteForRecipient(ctx, id, recipientUserID)
}

// GetIncomingInviteByToken retrieves an incoming invite by token scoped to a recipient.
func (d *Driver) GetIncomingInviteByToken(ctx context.Context, token string, recipientUserID string) (*store.IncomingInvite, error) {
	return d.core.GetIncomingInviteByToken(ctx, token, recipientUserID)
}

// UpdateIncomingInviteStatusForRecipient updates the status of an incoming invite scoped to a recipient.
func (d *Driver) UpdateIncomingInviteStatusForRecipient(ctx context.Context, id string, recipientUserID string, status string, senderUserID string, senderFQDNNormalized string) error {
	return d.core.UpdateIncomingInviteStatusForRecipient(ctx, id, recipientUserID, status, senderUserID, senderFQDNNormalized)
}

// DeleteIncomingInviteForRecipient deletes an incoming invite scoped to a recipient.
func (d *Driver) DeleteIncomingInviteForRecipient(ctx context.Context, id string, recipientUserID string) error {
	return d.core.DeleteIncomingInviteForRecipient(ctx, id, recipientUserID)
}

// ListIncomingInvites returns incoming invites for a recipient user.
func (d *Driver) ListIncomingInvites(ctx context.Context, recipientUserID string) ([]*store.IncomingInvite, error) {
	return d.core.ListIncomingInvites(ctx, recipientUserID)
}

// Compile-time interface checks
var _ store.Driver = (*Driver)(nil)
var _ store.OutgoingShareStore = (*Driver)(nil)
var _ store.IncomingShareStore = (*Driver)(nil)
var _ store.OutgoingInviteStore = (*Driver)(nil)
var _ store.IncomingInviteStore = (*Driver)(nil)
