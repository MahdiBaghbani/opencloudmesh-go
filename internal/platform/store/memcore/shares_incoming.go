// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package memcore

import (
	"context"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
)

// CreateIncomingShare creates a new incoming share.
func (c *Core) CreateIncomingShare(_ context.Context, share *store.IncomingShare) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return store.ErrClosed
	}

	if _, exists := c.incomingShares[share.ShareID]; exists {
		return store.ErrAlreadyExists
	}

	key := providerKey(share.SenderHost, share.ProviderID)
	if _, exists := c.providerIndex[key]; exists {
		return store.ErrAlreadyExists
	}

	c.incomingShares[share.ShareID] = cloneIncomingShare(share)
	c.providerIndex[key] = share.ShareID

	return nil
}

// GetIncomingShareByIDForRecipient retrieves an incoming share by shareID scoped to a recipient.
func (c *Core) GetIncomingShareByIDForRecipient(_ context.Context, shareID string, recipientUserID string) (*store.IncomingShare, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return nil, store.ErrClosed
	}

	share, ok := c.incomingShares[shareID]
	if !ok || share.RecipientUserID != recipientUserID {
		return nil, store.ErrNotFound
	}

	return cloneIncomingShare(share), nil
}

// GetIncomingShareByProviderKey retrieves an incoming share by sending server and providerID.
func (c *Core) GetIncomingShareByProviderKey(_ context.Context, senderHost, providerID string) (*store.IncomingShare, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return nil, store.ErrClosed
	}

	shareID, ok := c.providerIndex[providerKey(senderHost, providerID)]
	if !ok {
		return nil, store.ErrNotFound
	}

	share, ok := c.incomingShares[shareID]
	if !ok {
		return nil, store.ErrNotFound
	}

	return cloneIncomingShare(share), nil
}

// ListIncomingSharesByRecipient returns incoming shares for the given recipient user.
func (c *Core) ListIncomingSharesByRecipient(_ context.Context, recipientUserID string) ([]*store.IncomingShare, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return nil, store.ErrClosed
	}

	shares := make([]*store.IncomingShare, 0)

	for _, share := range c.incomingShares {
		if share.RecipientUserID == recipientUserID {
			shares = append(shares, cloneIncomingShare(share))
		}
	}

	return shares, nil
}

// UpdateIncomingShareStatusForRecipient updates the status of an incoming share, scoped to a recipient.
func (c *Core) UpdateIncomingShareStatusForRecipient(_ context.Context, shareID string, recipientUserID string, status string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return store.ErrClosed
	}

	share, exists := c.incomingShares[shareID]
	if !exists || share.RecipientUserID != recipientUserID {
		return store.ErrNotFound
	}

	share.Status = status
	share.UpdatedAt = time.Now().Unix()

	return nil
}

// DeleteIncomingShareForRecipient deletes an incoming share, scoped to a recipient.
func (c *Core) DeleteIncomingShareForRecipient(_ context.Context, shareID string, recipientUserID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return store.ErrClosed
	}

	share, exists := c.incomingShares[shareID]
	if !exists || share.RecipientUserID != recipientUserID {
		return store.ErrNotFound
	}

	delete(c.providerIndex, providerKey(share.SenderHost, share.ProviderID))
	delete(c.incomingShares, shareID)

	return nil
}
