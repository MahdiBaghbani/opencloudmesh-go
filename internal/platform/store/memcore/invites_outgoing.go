// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package memcore

import (
	"context"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
)

// validateCreateInviteStatus is the create-time status validation seam for
// outgoing invites. Status transition rules are not enforced here yet; Create
// routes through the hook so the validation point stays stable.
func validateCreateInviteStatus(_ *store.OutgoingInvite) {
}

// validateUpdateAcceptedIdentity applies the narrow accepted-identity
// invariant before Update replaces the stored record: the accepted user id
// and the normalized accepted provider host are coalesced from the stored
// record when the update leaves them empty, so a full-record replace cannot
// erase a persisted accepted identity. All other fields follow normal
// replace semantics; the hook writes no acceptance payload fields.
func validateUpdateAcceptedIdentity(existing, invite *store.OutgoingInvite) {
	if invite.AcceptedUserID == "" {
		invite.AcceptedUserID = existing.AcceptedUserID
	}

	if invite.AcceptedProviderFQDNNormalized == "" {
		invite.AcceptedProviderFQDNNormalized = existing.AcceptedProviderFQDNNormalized
	}
}

// CreateOutgoingInvite creates a new outgoing invite.
func (c *Core) CreateOutgoingInvite(_ context.Context, invite *store.OutgoingInvite) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return store.ErrClosed
	}

	if _, exists := c.outgoingInvites[invite.ID]; exists {
		return store.ErrAlreadyExists
	}

	if invite.Token != "" {
		if existing, ok := c.outgoingInviteTokenIndex[invite.Token]; ok && existing != invite.ID {
			return store.ErrAlreadyExists
		}
	}

	validateCreateInviteStatus(invite)

	c.outgoingInvites[invite.ID] = cloneOutgoingInvite(invite)
	if invite.Token != "" {
		c.outgoingInviteTokenIndex[invite.Token] = invite.ID
	}

	return nil
}

// GetOutgoingInvite retrieves an outgoing invite by id.
func (c *Core) GetOutgoingInvite(_ context.Context, id string) (*store.OutgoingInvite, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return nil, store.ErrClosed
	}

	invite, ok := c.outgoingInvites[id]
	if !ok {
		return nil, store.ErrNotFound
	}

	return cloneOutgoingInvite(invite), nil
}

// GetOutgoingInviteByToken retrieves an outgoing invite by token.
func (c *Core) GetOutgoingInviteByToken(_ context.Context, token string) (*store.OutgoingInvite, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return nil, store.ErrClosed
	}

	id, ok := c.outgoingInviteTokenIndex[token]
	if !ok {
		return nil, store.ErrNotFound
	}

	invite, ok := c.outgoingInvites[id]
	if !ok {
		return nil, store.ErrNotFound
	}

	return cloneOutgoingInvite(invite), nil
}

// UpdateOutgoingInvite updates an existing outgoing invite.
func (c *Core) UpdateOutgoingInvite(_ context.Context, invite *store.OutgoingInvite) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return store.ErrClosed
	}

	existing, exists := c.outgoingInvites[invite.ID]
	if !exists {
		return store.ErrNotFound
	}

	if invite.Token != "" {
		if existingID, ok := c.outgoingInviteTokenIndex[invite.Token]; ok && existingID != invite.ID {
			return store.ErrAlreadyExists
		}
	}

	validateUpdateAcceptedIdentity(existing, invite)

	for tok, id := range c.outgoingInviteTokenIndex {
		if id == invite.ID {
			delete(c.outgoingInviteTokenIndex, tok)

			break
		}
	}

	c.outgoingInvites[invite.ID] = cloneOutgoingInvite(invite)
	if invite.Token != "" {
		c.outgoingInviteTokenIndex[invite.Token] = invite.ID
	}

	return nil
}

// DeleteOutgoingInvite deletes an outgoing invite.
func (c *Core) DeleteOutgoingInvite(_ context.Context, id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return store.ErrClosed
	}

	invite, exists := c.outgoingInvites[id]
	if !exists {
		return store.ErrNotFound
	}

	if invite.Token != "" {
		delete(c.outgoingInviteTokenIndex, invite.Token)
	}

	delete(c.outgoingInvites, id)

	return nil
}

// ListOutgoingInvites returns outgoing invites for a user.
func (c *Core) ListOutgoingInvites(_ context.Context, userID string) ([]*store.OutgoingInvite, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return nil, store.ErrClosed
	}

	invites := make([]*store.OutgoingInvite, 0)

	for _, invite := range c.outgoingInvites {
		if userID == "" || invite.CreatedByUserID == userID {
			invites = append(invites, cloneOutgoingInvite(invite))
		}
	}

	return invites, nil
}
