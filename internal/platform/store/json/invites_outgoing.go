// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package json

import (
	"context"
	"fmt"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
)

// CreateOutgoingInvite creates a new outgoing invite.
func (d *Driver) CreateOutgoingInvite(_ context.Context, invite *store.OutgoingInvite) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return store.ErrClosed
	}

	if _, exists := d.outgoingInvites[invite.ID]; exists {
		return store.ErrAlreadyExists
	}

	if invite.Token != "" {
		if existing, ok := d.outgoingInviteTokenIndex[invite.Token]; ok && existing != invite.ID {
			return store.ErrAlreadyExists
		}
	}

	if err := invites.ValidateCreateInviteStatus(invite.Status, invite.AcceptedUserID, invite.AcceptedProviderFQDNNormalized); err != nil {
		return fmt.Errorf("store: validate create invite status: %w", err)
	}

	d.outgoingInvites[invite.ID] = cloneOutgoingInvite(invite)
	if invite.Token != "" {
		d.outgoingInviteTokenIndex[invite.Token] = invite.ID
	}

	if err := d.saveFile(fileOutgoingInvites, d.outgoingInvites); err != nil {
		// Rollback: remove the in-memory entry so state stays consistent with disk.
		delete(d.outgoingInvites, invite.ID)

		if invite.Token != "" {
			delete(d.outgoingInviteTokenIndex, invite.Token)
		}

		return err
	}

	return nil
}

// GetOutgoingInvite retrieves an outgoing invite by id.
func (d *Driver) GetOutgoingInvite(_ context.Context, id string) (*store.OutgoingInvite, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.closed {
		return nil, store.ErrClosed
	}

	invite, ok := d.outgoingInvites[id]
	if !ok {
		return nil, store.ErrNotFound
	}

	return cloneOutgoingInvite(invite), nil
}

// GetOutgoingInviteByToken retrieves an outgoing invite by token.
func (d *Driver) GetOutgoingInviteByToken(_ context.Context, token string) (*store.OutgoingInvite, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.closed {
		return nil, store.ErrClosed
	}

	id, ok := d.outgoingInviteTokenIndex[token]
	if !ok {
		return nil, store.ErrNotFound
	}

	invite, ok := d.outgoingInvites[id]
	if !ok {
		return nil, store.ErrNotFound
	}

	return cloneOutgoingInvite(invite), nil
}

// UpdateOutgoingInvite updates an existing outgoing invite. The accepted
// identity (user id plus normalized host) coalesces with the stored row so a
// status-only write cannot erase it, and an accepted status without a complete
// identity is rejected. The raw accepted provider FQDN keeps replace semantics.
func (d *Driver) UpdateOutgoingInvite(_ context.Context, invite *store.OutgoingInvite) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return store.ErrClosed
	}

	existing, exists := d.outgoingInvites[invite.ID]
	if !exists {
		return store.ErrNotFound
	}

	if err := invites.ValidateUpdateAcceptedIdentity(invite.Status,
		invite.AcceptedUserID, invite.AcceptedProviderFQDNNormalized,
		existing.AcceptedUserID, existing.AcceptedProviderFQDNNormalized); err != nil {
		return fmt.Errorf("store: validate update accepted identity: %w", err)
	}

	invite.AcceptedUserID, invite.AcceptedProviderFQDNNormalized = invites.CoalesceAcceptedIdentity(
		invite.AcceptedUserID, invite.AcceptedProviderFQDNNormalized,
		existing.AcceptedUserID, existing.AcceptedProviderFQDNNormalized)

	if invite.Token != "" {
		if existingID, ok := d.outgoingInviteTokenIndex[invite.Token]; ok && existingID != invite.ID {
			return store.ErrAlreadyExists
		}
	}

	// Capture old state for rollback.
	oldInvite := existing

	var oldToken string

	for tok, id := range d.outgoingInviteTokenIndex {
		if id == invite.ID {
			oldToken = tok
			delete(d.outgoingInviteTokenIndex, tok)

			break
		}
	}

	d.outgoingInvites[invite.ID] = cloneOutgoingInvite(invite)
	if invite.Token != "" {
		d.outgoingInviteTokenIndex[invite.Token] = invite.ID
	}

	if err := d.saveFile(fileOutgoingInvites, d.outgoingInvites); err != nil {
		// Rollback: restore old invite and old token index entry.
		d.outgoingInvites[invite.ID] = oldInvite
		if invite.Token != "" {
			delete(d.outgoingInviteTokenIndex, invite.Token)
		}

		if oldToken != "" {
			d.outgoingInviteTokenIndex[oldToken] = invite.ID
		}

		return err
	}

	return nil
}

// DeleteOutgoingInvite deletes an outgoing invite.
func (d *Driver) DeleteOutgoingInvite(_ context.Context, id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return store.ErrClosed
	}

	invite, exists := d.outgoingInvites[id]
	if !exists {
		return store.ErrNotFound
	}

	if invite.Token != "" {
		delete(d.outgoingInviteTokenIndex, invite.Token)
	}

	delete(d.outgoingInvites, id)

	if err := d.saveFile(fileOutgoingInvites, d.outgoingInvites); err != nil {
		// Rollback: restore deleted entry and its token index slot.
		d.outgoingInvites[id] = invite
		if invite.Token != "" {
			d.outgoingInviteTokenIndex[invite.Token] = id
		}

		return err
	}

	return nil
}

// ListOutgoingInvites returns outgoing invites for a user.
func (d *Driver) ListOutgoingInvites(_ context.Context, userID string) ([]*store.OutgoingInvite, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.closed {
		return nil, store.ErrClosed
	}

	invites := make([]*store.OutgoingInvite, 0)

	for _, invite := range d.outgoingInvites {
		if userID == "" || invite.CreatedByUserID == userID {
			invites = append(invites, cloneOutgoingInvite(invite))
		}
	}

	return invites, nil
}
