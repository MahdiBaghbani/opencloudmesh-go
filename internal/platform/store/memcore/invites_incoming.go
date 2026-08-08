// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package memcore

import (
	"context"
	"fmt"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
)

// CreateIncomingInvite creates a new incoming invite.
func (c *Core) CreateIncomingInvite(_ context.Context, invite *store.IncomingInvite) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return store.ErrClosed
	}

	if _, exists := c.incomingInvites[invite.ID]; exists {
		return store.ErrAlreadyExists
	}

	if invite.Token != "" && invite.RecipientUserID != "" {
		key := tokenUserKey(invite.Token, invite.RecipientUserID)
		if existing, ok := c.incomingInviteTokenUserIndex[key]; ok && existing != invite.ID {
			return store.ErrAlreadyExists
		}
	}

	if err := invites.ValidateCreateInviteStatus(invite.Status, invite.SenderUserID, invite.SenderFQDNNormalized); err != nil {
		return fmt.Errorf("store: validate create invite status: %w", err)
	}

	c.incomingInvites[invite.ID] = cloneIncomingInvite(invite)
	if invite.Token != "" && invite.RecipientUserID != "" {
		c.incomingInviteTokenUserIndex[tokenUserKey(invite.Token, invite.RecipientUserID)] = invite.ID
	}

	return nil
}

// GetIncomingInviteForRecipient retrieves an incoming invite by id scoped to a recipient.
func (c *Core) GetIncomingInviteForRecipient(
	_ context.Context,
	id string,
	recipientUserID string,
) (*store.IncomingInvite, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return nil, store.ErrClosed
	}

	invite, ok := c.incomingInvites[id]
	if !ok || invite.RecipientUserID != recipientUserID {
		return nil, store.ErrNotFound
	}

	return cloneIncomingInvite(invite), nil
}

// GetIncomingInviteByToken retrieves an incoming invite by token scoped to a recipient.
func (c *Core) GetIncomingInviteByToken(_ context.Context, token string, recipientUserID string) (*store.IncomingInvite, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return nil, store.ErrClosed
	}

	id, ok := c.incomingInviteTokenUserIndex[tokenUserKey(token, recipientUserID)]
	if !ok {
		return nil, store.ErrNotFound
	}

	invite, ok := c.incomingInvites[id]
	if !ok {
		return nil, store.ErrNotFound
	}

	return cloneIncomingInvite(invite), nil
}

// UpdateIncomingInviteStatusForRecipient updates the status of an incoming invite scoped
// to a recipient, persisting the remote sender identity on acceptance when provided.
// The write is intentionally narrow: besides status and updatedAt, only the sender
// user id and normalized sender host are written; scope-defining
// fields (Token, RecipientUserID) and all other payload fields are immutable here.
// The recipient scope gate runs before identity validation so a wrong recipient
// stays ErrNotFound. Sender identity coalesces with the stored row, and an
// accepted status without a complete identity is rejected.
func (c *Core) UpdateIncomingInviteStatusForRecipient(
	_ context.Context,
	id string,
	recipientUserID string,
	status string,
	senderUserID string,
	senderFQDNNormalized string,
) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return store.ErrClosed
	}

	existing, exists := c.incomingInvites[id]
	if !exists || existing.RecipientUserID != recipientUserID {
		return store.ErrNotFound
	}

	if err := invites.ValidateUpdateAcceptedIdentity(status, senderUserID, senderFQDNNormalized, existing.SenderUserID, existing.SenderFQDNNormalized); err != nil {
		return fmt.Errorf("store: validate update accepted identity: %w", err)
	}

	senderUserID, senderFQDNNormalized = invites.CoalesceAcceptedIdentity(
		senderUserID, senderFQDNNormalized, existing.SenderUserID, existing.SenderFQDNNormalized)

	existing.Status = status
	existing.UpdatedAt = time.Now().Unix()
	existing.SenderUserID = senderUserID
	existing.SenderFQDNNormalized = senderFQDNNormalized

	return nil
}

// DeleteIncomingInviteForRecipient deletes an incoming invite scoped to a recipient.
func (c *Core) DeleteIncomingInviteForRecipient(
	_ context.Context,
	id string,
	recipientUserID string,
) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return store.ErrClosed
	}

	invite, exists := c.incomingInvites[id]
	if !exists || invite.RecipientUserID != recipientUserID {
		return store.ErrNotFound
	}

	if invite.Token != "" && invite.RecipientUserID != "" {
		delete(c.incomingInviteTokenUserIndex, tokenUserKey(invite.Token, invite.RecipientUserID))
	}

	delete(c.incomingInvites, id)

	return nil
}

// ListIncomingInvites returns incoming invites for a recipient user.
func (c *Core) ListIncomingInvites(_ context.Context, recipientUserID string) ([]*store.IncomingInvite, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return nil, store.ErrClosed
	}

	invites := make([]*store.IncomingInvite, 0)

	for _, invite := range c.incomingInvites {
		if invite.RecipientUserID == recipientUserID {
			invites = append(invites, cloneIncomingInvite(invite))
		}
	}

	return invites, nil
}
