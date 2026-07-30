package json

import (
	"context"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
)

// CreateIncomingShare creates a new incoming share.
func (d *Driver) CreateIncomingShare(_ context.Context, share *store.IncomingShare) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return store.ErrClosed
	}

	if _, exists := d.incomingShares[share.ShareID]; exists {
		return store.ErrAlreadyExists
	}

	key := providerKey(share.SenderHost, share.ProviderID)
	if _, exists := d.providerIndex[key]; exists {
		return store.ErrAlreadyExists
	}

	d.incomingShares[share.ShareID] = cloneIncomingShare(share)
	d.providerIndex[key] = share.ShareID

	if err := d.saveFile(fileIncomingShares, d.incomingShares); err != nil {
		// Rollback: remove the in-memory entries so state stays consistent with disk.
		delete(d.incomingShares, share.ShareID)
		delete(d.providerIndex, key)

		return err
	}

	return nil
}

// GetIncomingShareByIDForRecipient retrieves an incoming share by shareID scoped to a recipient.
func (d *Driver) GetIncomingShareByIDForRecipient(_ context.Context, shareID string, recipientUserID string) (*store.IncomingShare, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.closed {
		return nil, store.ErrClosed
	}

	share, ok := d.incomingShares[shareID]
	if !ok || share.RecipientUserID != recipientUserID {
		return nil, store.ErrNotFound
	}

	return cloneIncomingShare(share), nil
}

// GetIncomingShareByProviderKey retrieves an incoming share by sending server and providerID.
func (d *Driver) GetIncomingShareByProviderKey(_ context.Context, senderHost, providerID string) (*store.IncomingShare, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.closed {
		return nil, store.ErrClosed
	}

	shareID, ok := d.providerIndex[providerKey(senderHost, providerID)]
	if !ok {
		return nil, store.ErrNotFound
	}

	share, ok := d.incomingShares[shareID]
	if !ok {
		return nil, store.ErrNotFound
	}

	return cloneIncomingShare(share), nil
}

// ListIncomingSharesByRecipient returns incoming shares for the given recipient user.
func (d *Driver) ListIncomingSharesByRecipient(_ context.Context, recipientUserID string) ([]*store.IncomingShare, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.closed {
		return nil, store.ErrClosed
	}

	shares := make([]*store.IncomingShare, 0)

	for _, share := range d.incomingShares {
		if share.RecipientUserID == recipientUserID {
			shares = append(shares, cloneIncomingShare(share))
		}
	}

	return shares, nil
}

// UpdateIncomingShareStatusForRecipient updates the status of an incoming share, scoped to a recipient.
func (d *Driver) UpdateIncomingShareStatusForRecipient(_ context.Context, shareID string, recipientUserID string, status string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return store.ErrClosed
	}

	share, exists := d.incomingShares[shareID]
	if !exists || share.RecipientUserID != recipientUserID {
		return store.ErrNotFound
	}

	oldStatus := share.Status
	oldUpdatedAt := share.UpdatedAt
	share.Status = status
	share.UpdatedAt = time.Now().Unix()

	if err := d.saveFile(fileIncomingShares, d.incomingShares); err != nil {
		// Rollback: restore the old field values on the in-place pointer.
		share.Status = oldStatus
		share.UpdatedAt = oldUpdatedAt

		return err
	}

	return nil
}

// DeleteIncomingShareForRecipient deletes an incoming share, scoped to a recipient.
func (d *Driver) DeleteIncomingShareForRecipient(_ context.Context, shareID string, recipientUserID string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return store.ErrClosed
	}

	share, exists := d.incomingShares[shareID]
	if !exists || share.RecipientUserID != recipientUserID {
		return store.ErrNotFound
	}

	key := providerKey(share.SenderHost, share.ProviderID)
	delete(d.providerIndex, key)
	delete(d.incomingShares, shareID)

	if err := d.saveFile(fileIncomingShares, d.incomingShares); err != nil {
		// Rollback: restore deleted entry and its provider index slot.
		d.incomingShares[shareID] = share
		d.providerIndex[key] = shareID

		return err
	}

	return nil
}
