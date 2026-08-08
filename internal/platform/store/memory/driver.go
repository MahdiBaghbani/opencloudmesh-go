// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// Package memory implements an in-memory persistence driver.
// It is a thin wrapper over the shared memcore.Core engine; nothing touches disk.
package memory

import (
	"context"
	"fmt"

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
	if err := d.core.Close(); err != nil {
		return fmt.Errorf("store: close database: %w", err)
	}

	return nil
}

// CreateOutgoingShare creates a new outgoing share.
func (d *Driver) CreateOutgoingShare(ctx context.Context, share *store.OutgoingShare) error {
	if err := d.core.CreateOutgoingShare(ctx, share); err != nil {
		return fmt.Errorf("store: create outgoing share: %w", err)
	}

	return nil
}

// GetOutgoingShareByID retrieves an outgoing share by its local share id.
func (d *Driver) GetOutgoingShareByID(ctx context.Context, shareID string) (*store.OutgoingShare, error) {
	share, err := d.core.GetOutgoingShareByID(ctx, shareID)
	if err != nil {
		return share, fmt.Errorf("store: get outgoing share by id: %w", err)
	}

	return share, nil
}

// GetOutgoingShare retrieves an outgoing share by provider id.
func (d *Driver) GetOutgoingShare(ctx context.Context, providerID string) (*store.OutgoingShare, error) {
	share, err := d.core.GetOutgoingShare(ctx, providerID)
	if err != nil {
		return share, fmt.Errorf("store: get outgoing share: %w", err)
	}

	return share, nil
}

// GetOutgoingShareByWebDAVID retrieves an outgoing share by webdav id.
func (d *Driver) GetOutgoingShareByWebDAVID(ctx context.Context, webdavID string) (*store.OutgoingShare, error) {
	share, err := d.core.GetOutgoingShareByWebDAVID(ctx, webdavID)
	if err != nil {
		return share, fmt.Errorf("store: get outgoing share by webdav id: %w", err)
	}

	return share, nil
}

// GetOutgoingShareBySharedSecret retrieves an outgoing share by shared secret.
func (d *Driver) GetOutgoingShareBySharedSecret(ctx context.Context, sharedSecret string) (*store.OutgoingShare, error) {
	share, err := d.core.GetOutgoingShareBySharedSecret(ctx, sharedSecret)
	if err != nil {
		return share, fmt.Errorf("store: get outgoing share by shared secret: %w", err)
	}

	return share, nil
}

// UpdateOutgoingShare updates an existing outgoing share.
func (d *Driver) UpdateOutgoingShare(ctx context.Context, share *store.OutgoingShare) error {
	if err := d.core.UpdateOutgoingShare(ctx, share); err != nil {
		return fmt.Errorf("store: update outgoing share: %w", err)
	}

	return nil
}

// DeleteOutgoingShare deletes an outgoing share by provider id.
func (d *Driver) DeleteOutgoingShare(ctx context.Context, providerID string) error {
	if err := d.core.DeleteOutgoingShare(ctx, providerID); err != nil {
		return fmt.Errorf("store: delete outgoing share: %w", err)
	}

	return nil
}

// ListOutgoingShares returns all outgoing shares.
func (d *Driver) ListOutgoingShares(ctx context.Context) ([]*store.OutgoingShare, error) {
	shares, err := d.core.ListOutgoingShares(ctx)
	if err != nil {
		return shares, fmt.Errorf("store: list outgoing shares: %w", err)
	}

	return shares, nil
}

// CreateIncomingShare creates a new incoming share.
func (d *Driver) CreateIncomingShare(ctx context.Context, share *store.IncomingShare) error {
	if err := d.core.CreateIncomingShare(ctx, share); err != nil {
		return fmt.Errorf("store: create incoming share: %w", err)
	}

	return nil
}

// GetIncomingShareByIDForRecipient retrieves an incoming share by share id scoped to a recipient.
func (d *Driver) GetIncomingShareByIDForRecipient(ctx context.Context, shareID string, recipientUserID string) (*store.IncomingShare, error) {
	share, err := d.core.GetIncomingShareByIDForRecipient(ctx, shareID, recipientUserID)
	if err != nil {
		return share, fmt.Errorf("store: get incoming share by id for recipient: %w", err)
	}

	return share, nil
}

// GetIncomingShareByProviderKey retrieves an incoming share by sending server and provider id.
func (d *Driver) GetIncomingShareByProviderKey(ctx context.Context, sendingServer, providerID string) (*store.IncomingShare, error) {
	share, err := d.core.GetIncomingShareByProviderKey(ctx, sendingServer, providerID)
	if err != nil {
		return share, fmt.Errorf("store: get incoming share by provider key: %w", err)
	}

	return share, nil
}

// ListIncomingSharesByRecipient returns incoming shares for the given recipient user.
func (d *Driver) ListIncomingSharesByRecipient(ctx context.Context, recipientUserID string) ([]*store.IncomingShare, error) {
	shares, err := d.core.ListIncomingSharesByRecipient(ctx, recipientUserID)
	if err != nil {
		return shares, fmt.Errorf("store: list incoming shares by recipient: %w", err)
	}

	return shares, nil
}

// UpdateIncomingShareStatusForRecipient updates the status of an incoming share scoped to a recipient.
func (d *Driver) UpdateIncomingShareStatusForRecipient(ctx context.Context, shareID string, recipientUserID string, status string) error {
	if err := d.core.UpdateIncomingShareStatusForRecipient(ctx, shareID, recipientUserID, status); err != nil {
		return fmt.Errorf("store: update incoming share status for recipient: %w", err)
	}

	return nil
}

// DeleteIncomingShareForRecipient deletes an incoming share scoped to a recipient.
func (d *Driver) DeleteIncomingShareForRecipient(ctx context.Context, shareID string, recipientUserID string) error {
	if err := d.core.DeleteIncomingShareForRecipient(ctx, shareID, recipientUserID); err != nil {
		return fmt.Errorf("store: delete incoming share for recipient: %w", err)
	}

	return nil
}

// CreateOutgoingInvite creates a new outgoing invite.
func (d *Driver) CreateOutgoingInvite(ctx context.Context, invite *store.OutgoingInvite) error {
	if err := d.core.CreateOutgoingInvite(ctx, invite); err != nil {
		return fmt.Errorf("store: create outgoing invite: %w", err)
	}

	return nil
}

// GetOutgoingInvite retrieves an outgoing invite by id.
func (d *Driver) GetOutgoingInvite(ctx context.Context, id string) (*store.OutgoingInvite, error) {
	invite, err := d.core.GetOutgoingInvite(ctx, id)
	if err != nil {
		return invite, fmt.Errorf("store: get outgoing invite: %w", err)
	}

	return invite, nil
}

// GetOutgoingInviteByToken retrieves an outgoing invite by token.
func (d *Driver) GetOutgoingInviteByToken(ctx context.Context, token string) (*store.OutgoingInvite, error) {
	invite, err := d.core.GetOutgoingInviteByToken(ctx, token)
	if err != nil {
		return invite, fmt.Errorf("store: get outgoing invite by token: %w", err)
	}

	return invite, nil
}

// UpdateOutgoingInvite updates an existing outgoing invite.
func (d *Driver) UpdateOutgoingInvite(ctx context.Context, invite *store.OutgoingInvite) error {
	if err := d.core.UpdateOutgoingInvite(ctx, invite); err != nil {
		return fmt.Errorf("store: update outgoing invite: %w", err)
	}

	return nil
}

// DeleteOutgoingInvite deletes an outgoing invite by id.
func (d *Driver) DeleteOutgoingInvite(ctx context.Context, id string) error {
	if err := d.core.DeleteOutgoingInvite(ctx, id); err != nil {
		return fmt.Errorf("store: delete outgoing invite: %w", err)
	}

	return nil
}

// ListOutgoingInvites returns outgoing invites for a user. An empty userID lists all invites.
func (d *Driver) ListOutgoingInvites(ctx context.Context, userID string) ([]*store.OutgoingInvite, error) {
	invites, err := d.core.ListOutgoingInvites(ctx, userID)
	if err != nil {
		return invites, fmt.Errorf("store: list outgoing invites: %w", err)
	}

	return invites, nil
}

// CreateIncomingInvite creates a new incoming invite.
func (d *Driver) CreateIncomingInvite(ctx context.Context, invite *store.IncomingInvite) error {
	if err := d.core.CreateIncomingInvite(ctx, invite); err != nil {
		return fmt.Errorf("store: create incoming invite: %w", err)
	}

	return nil
}

// GetIncomingInviteForRecipient retrieves an incoming invite by id scoped to a recipient.
func (d *Driver) GetIncomingInviteForRecipient(ctx context.Context, id string, recipientUserID string) (*store.IncomingInvite, error) {
	invite, err := d.core.GetIncomingInviteForRecipient(ctx, id, recipientUserID)
	if err != nil {
		return invite, fmt.Errorf("store: get incoming invite for recipient: %w", err)
	}

	return invite, nil
}

// GetIncomingInviteByToken retrieves an incoming invite by token scoped to a recipient.
func (d *Driver) GetIncomingInviteByToken(ctx context.Context, token string, recipientUserID string) (*store.IncomingInvite, error) {
	invite, err := d.core.GetIncomingInviteByToken(ctx, token, recipientUserID)
	if err != nil {
		return invite, fmt.Errorf("store: get incoming invite by token: %w", err)
	}

	return invite, nil
}

// UpdateIncomingInviteStatusForRecipient updates the status of an incoming invite scoped to a recipient.
func (d *Driver) UpdateIncomingInviteStatusForRecipient(ctx context.Context, id string, recipientUserID string, status string, senderUserID string, senderFQDNNormalized string) error {
	if err := d.core.UpdateIncomingInviteStatusForRecipient(ctx, id, recipientUserID, status, senderUserID, senderFQDNNormalized); err != nil {
		return fmt.Errorf("store: update incoming invite status for recipient: %w", err)
	}

	return nil
}

// DeleteIncomingInviteForRecipient deletes an incoming invite scoped to a recipient.
func (d *Driver) DeleteIncomingInviteForRecipient(ctx context.Context, id string, recipientUserID string) error {
	if err := d.core.DeleteIncomingInviteForRecipient(ctx, id, recipientUserID); err != nil {
		return fmt.Errorf("store: delete incoming invite for recipient: %w", err)
	}

	return nil
}

// ListIncomingInvites returns incoming invites for a recipient user.
func (d *Driver) ListIncomingInvites(ctx context.Context, recipientUserID string) ([]*store.IncomingInvite, error) {
	invites, err := d.core.ListIncomingInvites(ctx, recipientUserID)
	if err != nil {
		return invites, fmt.Errorf("store: list incoming invites: %w", err)
	}

	return invites, nil
}

// Compile-time interface checks.
var _ store.Driver = (*Driver)(nil)
var _ store.OutgoingShareStore = (*Driver)(nil)
var _ store.IncomingShareStore = (*Driver)(nil)
var _ store.OutgoingInviteStore = (*Driver)(nil)
var _ store.IncomingInviteStore = (*Driver)(nil)
