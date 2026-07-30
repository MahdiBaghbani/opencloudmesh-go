package json

import (
	"context"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
)

// CreateIncomingInvite creates a new incoming invite.
func (d *Driver) CreateIncomingInvite(_ context.Context, invite *store.IncomingInvite) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return store.ErrClosed
	}

	if _, exists := d.incomingInvites[invite.ID]; exists {
		return store.ErrAlreadyExists
	}

	if invite.Token != "" && invite.RecipientUserID != "" {
		key := tokenUserKey(invite.Token, invite.RecipientUserID)
		if existing, ok := d.incomingInviteTokenUserIndex[key]; ok && existing != invite.ID {
			return store.ErrAlreadyExists
		}
	}

	d.incomingInvites[invite.ID] = cloneIncomingInvite(invite)
	if invite.Token != "" && invite.RecipientUserID != "" {
		d.incomingInviteTokenUserIndex[tokenUserKey(invite.Token, invite.RecipientUserID)] = invite.ID
	}

	if err := d.saveFile(fileIncomingInvites, d.incomingInvites); err != nil {
		// Rollback: remove the in-memory entry so state stays consistent with disk.
		delete(d.incomingInvites, invite.ID)

		if invite.Token != "" && invite.RecipientUserID != "" {
			delete(d.incomingInviteTokenUserIndex, tokenUserKey(invite.Token, invite.RecipientUserID))
		}

		return err
	}

	return nil
}

// GetIncomingInviteForRecipient retrieves an incoming invite by id scoped to a recipient.
func (d *Driver) GetIncomingInviteForRecipient(
	_ context.Context,
	id string,
	recipientUserID string,
) (*store.IncomingInvite, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.closed {
		return nil, store.ErrClosed
	}

	invite, ok := d.incomingInvites[id]
	if !ok || invite.RecipientUserID != recipientUserID {
		return nil, store.ErrNotFound
	}

	return cloneIncomingInvite(invite), nil
}

// GetIncomingInviteByToken retrieves an incoming invite by token scoped to a recipient.
func (d *Driver) GetIncomingInviteByToken(_ context.Context, token string, recipientUserID string) (*store.IncomingInvite, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.closed {
		return nil, store.ErrClosed
	}

	id, ok := d.incomingInviteTokenUserIndex[tokenUserKey(token, recipientUserID)]
	if !ok {
		return nil, store.ErrNotFound
	}

	invite, ok := d.incomingInvites[id]
	if !ok {
		return nil, store.ErrNotFound
	}

	return cloneIncomingInvite(invite), nil
}

// UpdateIncomingInviteStatusForRecipient updates the status of an incoming invite scoped
// to a recipient, persisting the remote sender identity on acceptance when provided.
// Scope-defining fields (Token, RecipientUserID) are immutable after creation;
// callers cannot reassign them through this path.
func (d *Driver) UpdateIncomingInviteStatusForRecipient(
	_ context.Context,
	id string,
	recipientUserID string,
	status string,
	senderUserID string,
	senderFQDNNormalized string,
) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return store.ErrClosed
	}

	existing, exists := d.incomingInvites[id]
	if !exists || existing.RecipientUserID != recipientUserID {
		return store.ErrNotFound
	}

	oldStatus := existing.Status
	oldUpdatedAt := existing.UpdatedAt
	oldSenderUserID := existing.SenderUserID
	oldSenderFQDNNormalized := existing.SenderFQDNNormalized

	existing.Status = status
	existing.UpdatedAt = time.Now().Unix()

	if senderUserID != "" {
		existing.SenderUserID = senderUserID
	}

	if senderFQDNNormalized != "" {
		existing.SenderFQDNNormalized = senderFQDNNormalized
	}

	if err := d.saveFile(fileIncomingInvites, d.incomingInvites); err != nil {
		// Rollback: restore the old field values on the in-place pointer.
		existing.Status = oldStatus
		existing.UpdatedAt = oldUpdatedAt
		existing.SenderUserID = oldSenderUserID
		existing.SenderFQDNNormalized = oldSenderFQDNNormalized

		return err
	}

	return nil
}

// DeleteIncomingInviteForRecipient deletes an incoming invite scoped to a recipient.
func (d *Driver) DeleteIncomingInviteForRecipient(
	_ context.Context,
	id string,
	recipientUserID string,
) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return store.ErrClosed
	}

	invite, exists := d.incomingInvites[id]
	if !exists || invite.RecipientUserID != recipientUserID {
		return store.ErrNotFound
	}

	if invite.Token != "" && invite.RecipientUserID != "" {
		delete(d.incomingInviteTokenUserIndex, tokenUserKey(invite.Token, invite.RecipientUserID))
	}

	delete(d.incomingInvites, id)

	if err := d.saveFile(fileIncomingInvites, d.incomingInvites); err != nil {
		// Rollback: restore deleted entry and its token-user index slot.
		d.incomingInvites[id] = invite
		if invite.Token != "" && invite.RecipientUserID != "" {
			d.incomingInviteTokenUserIndex[tokenUserKey(invite.Token, invite.RecipientUserID)] = id
		}

		return err
	}

	return nil
}

// ListIncomingInvites returns incoming invites for a recipient user.
func (d *Driver) ListIncomingInvites(_ context.Context, recipientUserID string) ([]*store.IncomingInvite, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.closed {
		return nil, store.ErrClosed
	}

	invites := make([]*store.IncomingInvite, 0)

	for _, invite := range d.incomingInvites {
		if invite.RecipientUserID == recipientUserID {
			invites = append(invites, cloneIncomingInvite(invite))
		}
	}

	return invites, nil
}
