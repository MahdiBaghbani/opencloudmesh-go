package json

import (
	"context"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
)

// CreateIncomingShare creates a new incoming share.
func (d *Driver) CreateIncomingShare(ctx context.Context, share *store.IncomingShare) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return store.ErrClosed
	}

	if _, exists := d.incomingShares[share.ShareId]; exists {
		return store.ErrAlreadyExists
	}
	key := providerKey(share.SendingServer, share.ProviderId)
	if _, exists := d.providerIndex[key]; exists {
		return store.ErrAlreadyExists
	}

	d.incomingShares[share.ShareId] = cloneIncomingShare(share)
	d.providerIndex[key] = share.ShareId

	if err := d.saveFile(fileIncomingShares, d.incomingShares); err != nil {
		// Rollback: remove the in-memory entries so state stays consistent with disk.
		delete(d.incomingShares, share.ShareId)
		delete(d.providerIndex, key)
		return err
	}
	return nil
}

// GetIncomingShareByIDForRecipient retrieves an incoming share by shareId scoped to a recipient.
func (d *Driver) GetIncomingShareByIDForRecipient(ctx context.Context, shareId string, recipientUserId string) (*store.IncomingShare, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.closed {
		return nil, store.ErrClosed
	}

	share, ok := d.incomingShares[shareId]
	if !ok || share.UserId != recipientUserId {
		return nil, store.ErrNotFound
	}
	return cloneIncomingShare(share), nil
}

// GetIncomingShareByProviderKey retrieves an incoming share by sending server and providerId.
func (d *Driver) GetIncomingShareByProviderKey(ctx context.Context, sendingServer, providerId string) (*store.IncomingShare, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.closed {
		return nil, store.ErrClosed
	}

	shareId, ok := d.providerIndex[providerKey(sendingServer, providerId)]
	if !ok {
		return nil, store.ErrNotFound
	}

	share, ok := d.incomingShares[shareId]
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneIncomingShare(share), nil
}

// ListIncomingSharesByRecipient returns incoming shares for the given recipient user.
func (d *Driver) ListIncomingSharesByRecipient(ctx context.Context, recipientUserId string) ([]*store.IncomingShare, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.closed {
		return nil, store.ErrClosed
	}

	shares := make([]*store.IncomingShare, 0)
	for _, share := range d.incomingShares {
		if share.UserId == recipientUserId {
			shares = append(shares, cloneIncomingShare(share))
		}
	}
	return shares, nil
}

// UpdateIncomingShareStatusForRecipient updates the state of an incoming share, scoped to a recipient.
func (d *Driver) UpdateIncomingShareStatusForRecipient(ctx context.Context, shareId string, recipientUserId string, state string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return store.ErrClosed
	}

	share, exists := d.incomingShares[shareId]
	if !exists || share.UserId != recipientUserId {
		return store.ErrNotFound
	}

	oldState := share.State
	oldUpdatedAt := share.UpdatedAt
	share.State = state
	share.UpdatedAt = time.Now().Unix()

	if err := d.saveFile(fileIncomingShares, d.incomingShares); err != nil {
		// Rollback: restore the old field values on the in-place pointer.
		share.State = oldState
		share.UpdatedAt = oldUpdatedAt
		return err
	}
	return nil
}

// DeleteIncomingShareForRecipient deletes an incoming share, scoped to a recipient.
func (d *Driver) DeleteIncomingShareForRecipient(ctx context.Context, shareId string, recipientUserId string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return store.ErrClosed
	}

	share, exists := d.incomingShares[shareId]
	if !exists || share.UserId != recipientUserId {
		return store.ErrNotFound
	}

	key := providerKey(share.SendingServer, share.ProviderId)
	delete(d.providerIndex, key)
	delete(d.incomingShares, shareId)

	if err := d.saveFile(fileIncomingShares, d.incomingShares); err != nil {
		// Rollback: restore deleted entry and its provider index slot.
		d.incomingShares[shareId] = share
		d.providerIndex[key] = shareId
		return err
	}
	return nil
}
