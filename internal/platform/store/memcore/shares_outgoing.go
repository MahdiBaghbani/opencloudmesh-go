// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package memcore

import (
	"context"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
)

// CreateOutgoingShare creates a new outgoing share.
func (c *Core) CreateOutgoingShare(_ context.Context, share *store.OutgoingShare) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return store.ErrClosed
	}

	if _, exists := c.outgoingShares[share.ProviderID]; exists {
		return store.ErrAlreadyExists
	}

	if err := c.checkOutgoingShareIndexUnique(share); err != nil {
		return err
	}

	c.outgoingShares[share.ProviderID] = cloneOutgoingShare(share)
	c.setOutgoingShareIndexes(share)

	return nil
}

func (c *Core) checkOutgoingShareIndexUnique(share *store.OutgoingShare) error {
	if share.ShareID != "" {
		if existing, ok := c.shareIDIndex[share.ShareID]; ok && existing != share.ProviderID {
			return store.ErrAlreadyExists
		}
	}

	if share.WebDAVID != "" {
		if existing, ok := c.webdavIndex[share.WebDAVID]; ok && existing != share.ProviderID {
			return store.ErrAlreadyExists
		}
	}

	if share.SharedSecret != "" {
		if existing, ok := c.secretIndex[share.SharedSecret]; ok && existing != share.ProviderID {
			return store.ErrAlreadyExists
		}
	}

	return nil
}

func (c *Core) setOutgoingShareIndexes(share *store.OutgoingShare) {
	if share.WebDAVID != "" {
		c.webdavIndex[share.WebDAVID] = share.ProviderID
	}

	if share.ShareID != "" {
		c.shareIDIndex[share.ShareID] = share.ProviderID
	}

	if share.SharedSecret != "" {
		c.secretIndex[share.SharedSecret] = share.ProviderID
	}
}

func (c *Core) clearOutgoingShareIndexes(share *store.OutgoingShare) {
	if share.WebDAVID != "" {
		delete(c.webdavIndex, share.WebDAVID)
	}

	if share.ShareID != "" {
		delete(c.shareIDIndex, share.ShareID)
	}

	if share.SharedSecret != "" {
		delete(c.secretIndex, share.SharedSecret)
	}
}

// GetOutgoingShareByID retrieves an outgoing share by its local share id.
func (c *Core) GetOutgoingShareByID(_ context.Context, shareID string) (*store.OutgoingShare, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return nil, store.ErrClosed
	}

	providerID, ok := c.shareIDIndex[shareID]
	if !ok {
		return nil, store.ErrNotFound
	}

	share, ok := c.outgoingShares[providerID]
	if !ok {
		return nil, store.ErrNotFound
	}

	return cloneOutgoingShare(share), nil
}

// GetOutgoingShare retrieves an outgoing share by providerID.
func (c *Core) GetOutgoingShare(_ context.Context, providerID string) (*store.OutgoingShare, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return nil, store.ErrClosed
	}

	share, ok := c.outgoingShares[providerID]
	if !ok {
		return nil, store.ErrNotFound
	}

	return cloneOutgoingShare(share), nil
}

// GetOutgoingShareByWebDAVID retrieves an outgoing share by webdavID.
func (c *Core) GetOutgoingShareByWebDAVID(_ context.Context, webdavID string) (*store.OutgoingShare, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return nil, store.ErrClosed
	}

	providerID, ok := c.webdavIndex[webdavID]
	if !ok {
		return nil, store.ErrNotFound
	}

	share, ok := c.outgoingShares[providerID]
	if !ok {
		return nil, store.ErrNotFound
	}

	return cloneOutgoingShare(share), nil
}

// GetOutgoingShareBySharedSecret retrieves an outgoing share by shared secret.
func (c *Core) GetOutgoingShareBySharedSecret(_ context.Context, sharedSecret string) (*store.OutgoingShare, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return nil, store.ErrClosed
	}

	providerID, ok := c.secretIndex[sharedSecret]
	if !ok {
		return nil, store.ErrNotFound
	}

	share, ok := c.outgoingShares[providerID]
	if !ok {
		return nil, store.ErrNotFound
	}

	return cloneOutgoingShare(share), nil
}

// UpdateOutgoingShare updates an existing outgoing share.
func (c *Core) UpdateOutgoingShare(_ context.Context, share *store.OutgoingShare) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return store.ErrClosed
	}

	if _, exists := c.outgoingShares[share.ProviderID]; !exists {
		return store.ErrNotFound
	}

	if err := c.checkOutgoingShareIndexUnique(share); err != nil {
		return err
	}

	c.clearOutgoingProviderIndexes(share.ProviderID)
	c.outgoingShares[share.ProviderID] = cloneOutgoingShare(share)
	c.setOutgoingShareIndexes(share)

	return nil
}

// clearOutgoingProviderIndexes removes every secondary index entry pointing at
// providerID so an update can re-index from the replacement record.
func (c *Core) clearOutgoingProviderIndexes(providerID string) {
	for webdavID, pid := range c.webdavIndex {
		if pid == providerID {
			delete(c.webdavIndex, webdavID)
		}
	}

	for sID, pid := range c.shareIDIndex {
		if pid == providerID {
			delete(c.shareIDIndex, sID)
		}
	}

	for secret, pid := range c.secretIndex {
		if pid == providerID {
			delete(c.secretIndex, secret)
		}
	}
}

// DeleteOutgoingShare deletes an outgoing share.
func (c *Core) DeleteOutgoingShare(_ context.Context, providerID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return store.ErrClosed
	}

	share, exists := c.outgoingShares[providerID]
	if !exists {
		return store.ErrNotFound
	}

	c.clearOutgoingShareIndexes(share)
	delete(c.outgoingShares, providerID)

	return nil
}

// ListOutgoingShares returns all outgoing shares.
func (c *Core) ListOutgoingShares(_ context.Context) ([]*store.OutgoingShare, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return nil, store.ErrClosed
	}

	shares := make([]*store.OutgoingShare, 0, len(c.outgoingShares))
	for _, share := range c.outgoingShares {
		shares = append(shares, cloneOutgoingShare(share))
	}

	return shares, nil
}
