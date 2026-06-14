package json

import (
	"context"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
)

// CreateOutgoingInvite creates a new outgoing invite.
func (d *Driver) CreateOutgoingInvite(ctx context.Context, invite *store.OutgoingInvite) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return store.ErrClosed
	}

	if _, exists := d.outgoingInvites[invite.ID]; exists {
		return store.ErrAlreadyExists
	}
	if invite.Token != "" {
		if existing, ok := d.outgoingInviteTokenIndex[invite.Token]; ok && existing != invite.ID {
			return store.ErrAlreadyExists
		}
	}

	d.outgoingInvites[invite.ID] = cloneOutgoingInvite(invite)
	if invite.Token != "" {
		d.outgoingInviteTokenIndex[invite.Token] = invite.ID
	}

	if err := d.saveFile(fileOutgoingInvites, d.outgoingInvites); err != nil {
		// Rollback: remove the in-memory entry so state stays consistent with disk.
		delete(d.outgoingInvites, invite.ID)
		if invite.Token != "" {
			delete(d.outgoingInviteTokenIndex, invite.Token)
		}
		return err
	}
	return nil
}

// GetOutgoingInvite retrieves an outgoing invite by id.
func (d *Driver) GetOutgoingInvite(ctx context.Context, id string) (*store.OutgoingInvite, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.closed {
		return nil, store.ErrClosed
	}

	invite, ok := d.outgoingInvites[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneOutgoingInvite(invite), nil
}

// GetOutgoingInviteByToken retrieves an outgoing invite by token.
func (d *Driver) GetOutgoingInviteByToken(ctx context.Context, token string) (*store.OutgoingInvite, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.closed {
		return nil, store.ErrClosed
	}

	id, ok := d.outgoingInviteTokenIndex[token]
	if !ok {
		return nil, store.ErrNotFound
	}
	invite, ok := d.outgoingInvites[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneOutgoingInvite(invite), nil
}

// UpdateOutgoingInvite updates an existing outgoing invite.
func (d *Driver) UpdateOutgoingInvite(ctx context.Context, invite *store.OutgoingInvite) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return store.ErrClosed
	}

	if _, exists := d.outgoingInvites[invite.ID]; !exists {
		return store.ErrNotFound
	}
	if invite.Token != "" {
		if existing, ok := d.outgoingInviteTokenIndex[invite.Token]; ok && existing != invite.ID {
			return store.ErrAlreadyExists
		}
	}

	// Capture old state for rollback.
	oldInvite := d.outgoingInvites[invite.ID]
	var oldToken string
	for tok, id := range d.outgoingInviteTokenIndex {
		if id == invite.ID {
			oldToken = tok
			delete(d.outgoingInviteTokenIndex, tok)
			break
		}
	}

	d.outgoingInvites[invite.ID] = cloneOutgoingInvite(invite)
	if invite.Token != "" {
		d.outgoingInviteTokenIndex[invite.Token] = invite.ID
	}

	if err := d.saveFile(fileOutgoingInvites, d.outgoingInvites); err != nil {
		// Rollback: restore old invite and old token index entry.
		d.outgoingInvites[invite.ID] = oldInvite
		if invite.Token != "" {
			delete(d.outgoingInviteTokenIndex, invite.Token)
		}
		if oldToken != "" {
			d.outgoingInviteTokenIndex[oldToken] = invite.ID
		}
		return err
	}
	return nil
}

// DeleteOutgoingInvite deletes an outgoing invite.
func (d *Driver) DeleteOutgoingInvite(ctx context.Context, id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return store.ErrClosed
	}

	invite, exists := d.outgoingInvites[id]
	if !exists {
		return store.ErrNotFound
	}

	if invite.Token != "" {
		delete(d.outgoingInviteTokenIndex, invite.Token)
	}
	delete(d.outgoingInvites, id)

	if err := d.saveFile(fileOutgoingInvites, d.outgoingInvites); err != nil {
		// Rollback: restore deleted entry and its token index slot.
		d.outgoingInvites[id] = invite
		if invite.Token != "" {
			d.outgoingInviteTokenIndex[invite.Token] = id
		}
		return err
	}
	return nil
}

// ListOutgoingInvites returns outgoing invites for a user.
func (d *Driver) ListOutgoingInvites(ctx context.Context, userId string) ([]*store.OutgoingInvite, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.closed {
		return nil, store.ErrClosed
	}

	invites := make([]*store.OutgoingInvite, 0)
	for _, invite := range d.outgoingInvites {
		if userId == "" || invite.CreatedByUserId == userId {
			invites = append(invites, cloneOutgoingInvite(invite))
		}
	}
	return invites, nil
}
