package json

import (
	"context"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
)

// CreateIncomingInvite creates a new incoming invite.
func (d *Driver) CreateIncomingInvite(ctx context.Context, invite *store.IncomingInvite) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return store.ErrClosed
	}

	if _, exists := d.incomingInvites[invite.ID]; exists {
		return store.ErrAlreadyExists
	}
	if invite.Token != "" && invite.RecipientUserId != "" {
		key := tokenUserKey(invite.Token, invite.RecipientUserId)
		if existing, ok := d.incomingInviteTokenUserIndex[key]; ok && existing != invite.ID {
			return store.ErrAlreadyExists
		}
	}

	d.incomingInvites[invite.ID] = cloneIncomingInvite(invite)
	if invite.Token != "" && invite.RecipientUserId != "" {
		d.incomingInviteTokenUserIndex[tokenUserKey(invite.Token, invite.RecipientUserId)] = invite.ID
	}

	if err := d.saveFile(fileIncomingInvites, d.incomingInvites); err != nil {
		// Rollback: remove the in-memory entry so state stays consistent with disk.
		delete(d.incomingInvites, invite.ID)
		if invite.Token != "" && invite.RecipientUserId != "" {
			delete(d.incomingInviteTokenUserIndex, tokenUserKey(invite.Token, invite.RecipientUserId))
		}
		return err
	}
	return nil
}

// GetIncomingInviteForRecipient retrieves an incoming invite by id scoped to a recipient.
func (d *Driver) GetIncomingInviteForRecipient(
	ctx context.Context,
	id string,
	recipientUserId string,
) (*store.IncomingInvite, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.closed {
		return nil, store.ErrClosed
	}

	invite, ok := d.incomingInvites[id]
	if !ok || invite.RecipientUserId != recipientUserId {
		return nil, store.ErrNotFound
	}
	return cloneIncomingInvite(invite), nil
}

// GetIncomingInviteByToken retrieves an incoming invite by token scoped to a recipient.
func (d *Driver) GetIncomingInviteByToken(ctx context.Context, token string, recipientUserId string) (*store.IncomingInvite, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.closed {
		return nil, store.ErrClosed
	}

	id, ok := d.incomingInviteTokenUserIndex[tokenUserKey(token, recipientUserId)]
	if !ok {
		return nil, store.ErrNotFound
	}
	invite, ok := d.incomingInvites[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneIncomingInvite(invite), nil
}

// UpdateIncomingInviteStatusForRecipient updates only the status of an incoming invite scoped
// to a recipient. Scope-defining fields (Token, RecipientUserId) are immutable after creation;
// callers cannot reassign them through this path.
func (d *Driver) UpdateIncomingInviteStatusForRecipient(
	ctx context.Context,
	id string,
	recipientUserId string,
	status string,
) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return store.ErrClosed
	}

	existing, exists := d.incomingInvites[id]
	if !exists || existing.RecipientUserId != recipientUserId {
		return store.ErrNotFound
	}

	oldStatus := existing.Status
	oldUpdatedAt := existing.UpdatedAt
	existing.Status = status
	existing.UpdatedAt = time.Now().Unix()

	if err := d.saveFile(fileIncomingInvites, d.incomingInvites); err != nil {
		// Rollback: restore the old field values on the in-place pointer.
		existing.Status = oldStatus
		existing.UpdatedAt = oldUpdatedAt
		return err
	}
	return nil
}

// DeleteIncomingInviteForRecipient deletes an incoming invite scoped to a recipient.
func (d *Driver) DeleteIncomingInviteForRecipient(
	ctx context.Context,
	id string,
	recipientUserId string,
) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return store.ErrClosed
	}

	invite, exists := d.incomingInvites[id]
	if !exists || invite.RecipientUserId != recipientUserId {
		return store.ErrNotFound
	}

	if invite.Token != "" && invite.RecipientUserId != "" {
		delete(d.incomingInviteTokenUserIndex, tokenUserKey(invite.Token, invite.RecipientUserId))
	}
	delete(d.incomingInvites, id)

	if err := d.saveFile(fileIncomingInvites, d.incomingInvites); err != nil {
		// Rollback: restore deleted entry and its token-user index slot.
		d.incomingInvites[id] = invite
		if invite.Token != "" && invite.RecipientUserId != "" {
			d.incomingInviteTokenUserIndex[tokenUserKey(invite.Token, invite.RecipientUserId)] = id
		}
		return err
	}
	return nil
}

// ListIncomingInvites returns incoming invites for a recipient user.
func (d *Driver) ListIncomingInvites(ctx context.Context, recipientUserId string) ([]*store.IncomingInvite, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.closed {
		return nil, store.ErrClosed
	}

	invites := make([]*store.IncomingInvite, 0)
	for _, invite := range d.incomingInvites {
		if invite.RecipientUserId == recipientUserId {
			invites = append(invites, cloneIncomingInvite(invite))
		}
	}
	return invites, nil
}
