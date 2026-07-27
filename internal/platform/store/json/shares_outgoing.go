package json

import (
	"context"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
)

// CreateOutgoingShare creates a new outgoing share.
func (d *Driver) CreateOutgoingShare(ctx context.Context, share *store.OutgoingShare) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return store.ErrClosed
	}

	if _, exists := d.outgoingShares[share.ProviderId]; exists {
		return store.ErrAlreadyExists
	}

	if err := d.checkOutgoingShareIndexUnique(share); err != nil {
		return err
	}

	d.outgoingShares[share.ProviderId] = cloneOutgoingShare(share)
	d.setOutgoingShareIndexes(share)

	if err := d.saveFile(fileOutgoingShares, d.outgoingShares); err != nil {
		// Rollback: remove the in-memory entries so state stays consistent with disk.
		delete(d.outgoingShares, share.ProviderId)
		d.clearOutgoingShareIndexes(share)

		return err
	}

	return nil
}

func (d *Driver) checkOutgoingShareIndexUnique(share *store.OutgoingShare) error {
	if share.ShareId != "" {
		if existing, ok := d.shareIdIndex[share.ShareId]; ok && existing != share.ProviderId {
			return store.ErrAlreadyExists
		}
	}

	if share.WebDAVId != "" {
		if existing, ok := d.webdavIndex[share.WebDAVId]; ok && existing != share.ProviderId {
			return store.ErrAlreadyExists
		}
	}

	if share.SharedSecret != "" {
		if existing, ok := d.secretIndex[share.SharedSecret]; ok && existing != share.ProviderId {
			return store.ErrAlreadyExists
		}
	}

	return nil
}

func (d *Driver) setOutgoingShareIndexes(share *store.OutgoingShare) {
	if share.WebDAVId != "" {
		d.webdavIndex[share.WebDAVId] = share.ProviderId
	}

	if share.ShareId != "" {
		d.shareIdIndex[share.ShareId] = share.ProviderId
	}

	if share.SharedSecret != "" {
		d.secretIndex[share.SharedSecret] = share.ProviderId
	}
}

func (d *Driver) clearOutgoingShareIndexes(share *store.OutgoingShare) {
	if share.WebDAVId != "" {
		delete(d.webdavIndex, share.WebDAVId)
	}

	if share.ShareId != "" {
		delete(d.shareIdIndex, share.ShareId)
	}

	if share.SharedSecret != "" {
		delete(d.secretIndex, share.SharedSecret)
	}
}

// GetOutgoingShareByID retrieves an outgoing share by its local share id.
func (d *Driver) GetOutgoingShareByID(ctx context.Context, shareId string) (*store.OutgoingShare, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.closed {
		return nil, store.ErrClosed
	}

	providerId, ok := d.shareIdIndex[shareId]
	if !ok {
		return nil, store.ErrNotFound
	}

	share, ok := d.outgoingShares[providerId]
	if !ok {
		return nil, store.ErrNotFound
	}

	return cloneOutgoingShare(share), nil
}

// GetOutgoingShare retrieves an outgoing share by providerId.
func (d *Driver) GetOutgoingShare(ctx context.Context, providerId string) (*store.OutgoingShare, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.closed {
		return nil, store.ErrClosed
	}

	share, ok := d.outgoingShares[providerId]
	if !ok {
		return nil, store.ErrNotFound
	}

	return cloneOutgoingShare(share), nil
}

// GetOutgoingShareByWebDAVId retrieves an outgoing share by webdavId.
func (d *Driver) GetOutgoingShareByWebDAVId(ctx context.Context, webdavId string) (*store.OutgoingShare, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.closed {
		return nil, store.ErrClosed
	}

	providerId, ok := d.webdavIndex[webdavId]
	if !ok {
		return nil, store.ErrNotFound
	}

	share, ok := d.outgoingShares[providerId]
	if !ok {
		return nil, store.ErrNotFound
	}

	return cloneOutgoingShare(share), nil
}

// GetOutgoingShareBySharedSecret retrieves an outgoing share by shared secret.
func (d *Driver) GetOutgoingShareBySharedSecret(ctx context.Context, sharedSecret string) (*store.OutgoingShare, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.closed {
		return nil, store.ErrClosed
	}

	providerId, ok := d.secretIndex[sharedSecret]
	if !ok {
		return nil, store.ErrNotFound
	}

	share, ok := d.outgoingShares[providerId]
	if !ok {
		return nil, store.ErrNotFound
	}

	return cloneOutgoingShare(share), nil
}

// UpdateOutgoingShare updates an existing outgoing share.
func (d *Driver) UpdateOutgoingShare(ctx context.Context, share *store.OutgoingShare) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return store.ErrClosed
	}

	if _, exists := d.outgoingShares[share.ProviderId]; !exists {
		return store.ErrNotFound
	}

	if err := d.checkOutgoingShareIndexUnique(share); err != nil {
		return err
	}

	// Capture old state for rollback, then clear stale index entries.
	oldShare := d.outgoingShares[share.ProviderId]
	oldWebDAVId, oldShareId, oldSecret := d.clearOutgoingProviderIndexes(share.ProviderId)

	d.outgoingShares[share.ProviderId] = cloneOutgoingShare(share)
	d.setOutgoingShareIndexes(share)

	if err := d.saveFile(fileOutgoingShares, d.outgoingShares); err != nil {
		// Rollback: restore old share and old index entries.
		d.outgoingShares[share.ProviderId] = oldShare
		d.clearOutgoingShareIndexes(share)
		d.restoreOutgoingProviderIndexes(share.ProviderId, oldWebDAVId, oldShareId, oldSecret)

		return err
	}

	return nil
}

func (d *Driver) clearOutgoingProviderIndexes(providerId string) (oldWebDAVId, oldShareId, oldSecret string) {
	for webdavId, pid := range d.webdavIndex {
		if pid == providerId {
			oldWebDAVId = webdavId
			delete(d.webdavIndex, webdavId)
		}
	}

	for sId, pid := range d.shareIdIndex {
		if pid == providerId {
			oldShareId = sId
			delete(d.shareIdIndex, sId)
		}
	}

	for secret, pid := range d.secretIndex {
		if pid == providerId {
			oldSecret = secret
			delete(d.secretIndex, secret)
		}
	}

	return oldWebDAVId, oldShareId, oldSecret
}

func (d *Driver) restoreOutgoingProviderIndexes(providerId, oldWebDAVId, oldShareId, oldSecret string) {
	if oldWebDAVId != "" {
		d.webdavIndex[oldWebDAVId] = providerId
	}

	if oldShareId != "" {
		d.shareIdIndex[oldShareId] = providerId
	}

	if oldSecret != "" {
		d.secretIndex[oldSecret] = providerId
	}
}

// DeleteOutgoingShare deletes an outgoing share.
func (d *Driver) DeleteOutgoingShare(ctx context.Context, providerId string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return store.ErrClosed
	}

	share, exists := d.outgoingShares[providerId]
	if !exists {
		return store.ErrNotFound
	}

	if share.WebDAVId != "" {
		delete(d.webdavIndex, share.WebDAVId)
	}

	if share.ShareId != "" {
		delete(d.shareIdIndex, share.ShareId)
	}

	if share.SharedSecret != "" {
		delete(d.secretIndex, share.SharedSecret)
	}

	delete(d.outgoingShares, providerId)

	if err := d.saveFile(fileOutgoingShares, d.outgoingShares); err != nil {
		// Rollback: restore deleted entry and its index slots.
		d.outgoingShares[providerId] = share
		if share.WebDAVId != "" {
			d.webdavIndex[share.WebDAVId] = providerId
		}

		if share.ShareId != "" {
			d.shareIdIndex[share.ShareId] = providerId
		}

		if share.SharedSecret != "" {
			d.secretIndex[share.SharedSecret] = providerId
		}

		return err
	}

	return nil
}

// ListOutgoingShares returns all outgoing shares.
func (d *Driver) ListOutgoingShares(ctx context.Context) ([]*store.OutgoingShare, error) {
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
