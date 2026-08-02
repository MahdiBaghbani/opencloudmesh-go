// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package json

import (
	"context"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
)

// CreateOutgoingShare creates a new outgoing share.
func (d *Driver) CreateOutgoingShare(_ context.Context, share *store.OutgoingShare) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return store.ErrClosed
	}

	if _, exists := d.outgoingShares[share.ProviderID]; exists {
		return store.ErrAlreadyExists
	}

	if err := d.checkOutgoingShareIndexUnique(share); err != nil {
		return err
	}

	d.outgoingShares[share.ProviderID] = cloneOutgoingShare(share)
	d.setOutgoingShareIndexes(share)

	if err := d.saveFile(fileOutgoingShares, d.outgoingShares); err != nil {
		// Rollback: remove the in-memory entries so state stays consistent with disk.
		delete(d.outgoingShares, share.ProviderID)
		d.clearOutgoingShareIndexes(share)

		return err
	}

	return nil
}

func (d *Driver) checkOutgoingShareIndexUnique(share *store.OutgoingShare) error {
	if share.ShareID != "" {
		if existing, ok := d.shareIDIndex[share.ShareID]; ok && existing != share.ProviderID {
			return store.ErrAlreadyExists
		}
	}

	if share.WebDAVID != "" {
		if existing, ok := d.webdavIndex[share.WebDAVID]; ok && existing != share.ProviderID {
			return store.ErrAlreadyExists
		}
	}

	if share.SharedSecret != "" {
		if existing, ok := d.secretIndex[share.SharedSecret]; ok && existing != share.ProviderID {
			return store.ErrAlreadyExists
		}
	}

	return nil
}

func (d *Driver) setOutgoingShareIndexes(share *store.OutgoingShare) {
	if share.WebDAVID != "" {
		d.webdavIndex[share.WebDAVID] = share.ProviderID
	}

	if share.ShareID != "" {
		d.shareIDIndex[share.ShareID] = share.ProviderID
	}

	if share.SharedSecret != "" {
		d.secretIndex[share.SharedSecret] = share.ProviderID
	}
}

func (d *Driver) clearOutgoingShareIndexes(share *store.OutgoingShare) {
	if share.WebDAVID != "" {
		delete(d.webdavIndex, share.WebDAVID)
	}

	if share.ShareID != "" {
		delete(d.shareIDIndex, share.ShareID)
	}

	if share.SharedSecret != "" {
		delete(d.secretIndex, share.SharedSecret)
	}
}

// GetOutgoingShareByID retrieves an outgoing share by its local share id.
func (d *Driver) GetOutgoingShareByID(_ context.Context, shareID string) (*store.OutgoingShare, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.closed {
		return nil, store.ErrClosed
	}

	providerID, ok := d.shareIDIndex[shareID]
	if !ok {
		return nil, store.ErrNotFound
	}

	share, ok := d.outgoingShares[providerID]
	if !ok {
		return nil, store.ErrNotFound
	}

	return cloneOutgoingShare(share), nil
}

// GetOutgoingShare retrieves an outgoing share by providerID.
func (d *Driver) GetOutgoingShare(_ context.Context, providerID string) (*store.OutgoingShare, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.closed {
		return nil, store.ErrClosed
	}

	share, ok := d.outgoingShares[providerID]
	if !ok {
		return nil, store.ErrNotFound
	}

	return cloneOutgoingShare(share), nil
}

// GetOutgoingShareByWebDAVID retrieves an outgoing share by webdavID.
func (d *Driver) GetOutgoingShareByWebDAVID(_ context.Context, webdavID string) (*store.OutgoingShare, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.closed {
		return nil, store.ErrClosed
	}

	providerID, ok := d.webdavIndex[webdavID]
	if !ok {
		return nil, store.ErrNotFound
	}

	share, ok := d.outgoingShares[providerID]
	if !ok {
		return nil, store.ErrNotFound
	}

	return cloneOutgoingShare(share), nil
}

// GetOutgoingShareBySharedSecret retrieves an outgoing share by shared secret.
func (d *Driver) GetOutgoingShareBySharedSecret(_ context.Context, sharedSecret string) (*store.OutgoingShare, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.closed {
		return nil, store.ErrClosed
	}

	providerID, ok := d.secretIndex[sharedSecret]
	if !ok {
		return nil, store.ErrNotFound
	}

	share, ok := d.outgoingShares[providerID]
	if !ok {
		return nil, store.ErrNotFound
	}

	return cloneOutgoingShare(share), nil
}

// UpdateOutgoingShare updates an existing outgoing share.
func (d *Driver) UpdateOutgoingShare(_ context.Context, share *store.OutgoingShare) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return store.ErrClosed
	}

	if _, exists := d.outgoingShares[share.ProviderID]; !exists {
		return store.ErrNotFound
	}

	if err := d.checkOutgoingShareIndexUnique(share); err != nil {
		return err
	}

	// Capture old state for rollback, then clear stale index entries.
	oldShare := d.outgoingShares[share.ProviderID]
	oldWebDAVID, oldShareID, oldSecret := d.clearOutgoingProviderIndexes(share.ProviderID)

	d.outgoingShares[share.ProviderID] = cloneOutgoingShare(share)
	d.setOutgoingShareIndexes(share)

	if err := d.saveFile(fileOutgoingShares, d.outgoingShares); err != nil {
		// Rollback: restore old share and old index entries.
		d.outgoingShares[share.ProviderID] = oldShare
		d.clearOutgoingShareIndexes(share)
		d.restoreOutgoingProviderIndexes(share.ProviderID, oldWebDAVID, oldShareID, oldSecret)

		return err
	}

	return nil
}

func (d *Driver) clearOutgoingProviderIndexes(providerID string) (oldWebDAVID, oldShareID, oldSecret string) {
	for webdavID, pid := range d.webdavIndex {
		if pid == providerID {
			oldWebDAVID = webdavID
			delete(d.webdavIndex, webdavID)
		}
	}

	for sID, pid := range d.shareIDIndex {
		if pid == providerID {
			oldShareID = sID
			delete(d.shareIDIndex, sID)
		}
	}

	for secret, pid := range d.secretIndex {
		if pid == providerID {
			oldSecret = secret
			delete(d.secretIndex, secret)
		}
	}

	return oldWebDAVID, oldShareID, oldSecret
}

func (d *Driver) restoreOutgoingProviderIndexes(providerID, oldWebDAVID, oldShareID, oldSecret string) {
	if oldWebDAVID != "" {
		d.webdavIndex[oldWebDAVID] = providerID
	}

	if oldShareID != "" {
		d.shareIDIndex[oldShareID] = providerID
	}

	if oldSecret != "" {
		d.secretIndex[oldSecret] = providerID
	}
}

// DeleteOutgoingShare deletes an outgoing share.
func (d *Driver) DeleteOutgoingShare(_ context.Context, providerID string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return store.ErrClosed
	}

	share, exists := d.outgoingShares[providerID]
	if !exists {
		return store.ErrNotFound
	}

	if share.WebDAVID != "" {
		delete(d.webdavIndex, share.WebDAVID)
	}

	if share.ShareID != "" {
		delete(d.shareIDIndex, share.ShareID)
	}

	if share.SharedSecret != "" {
		delete(d.secretIndex, share.SharedSecret)
	}

	delete(d.outgoingShares, providerID)

	if err := d.saveFile(fileOutgoingShares, d.outgoingShares); err != nil {
		// Rollback: restore deleted entry and its index slots.
		d.outgoingShares[providerID] = share
		if share.WebDAVID != "" {
			d.webdavIndex[share.WebDAVID] = providerID
		}

		if share.ShareID != "" {
			d.shareIDIndex[share.ShareID] = providerID
		}

		if share.SharedSecret != "" {
			d.secretIndex[share.SharedSecret] = providerID
		}

		return err
	}

	return nil
}

// ListOutgoingShares returns all outgoing shares.
func (d *Driver) ListOutgoingShares(_ context.Context) ([]*store.OutgoingShare, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.closed {
		return nil, store.ErrClosed
	}

	shares := make([]*store.OutgoingShare, 0, len(d.outgoingShares))
	for _, share := range d.outgoingShares {
		shares = append(shares, cloneOutgoingShare(share))
	}

	return shares, nil
}
