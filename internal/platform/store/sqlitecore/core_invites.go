// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package sqlitecore

import (
	"context"
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
)

// ----------------------------------------------------------------------------
// OutgoingInvite CRUD
// ----------------------------------------------------------------------------

// CreateOutgoingInvite creates a new outgoing invite.
func (c *Core) CreateOutgoingInvite(ctx context.Context, invite *store.OutgoingInvite) error {
	if err := invites.ValidateCreateInviteStatus(invite.Status, invite.AcceptedUserID, invite.AcceptedProviderFQDNNormalized); err != nil {
		return fmt.Errorf("store: validate create invite status: %w", err)
	}

	if err := c.db.WithContext(ctx).Create(invite).Error; err != nil {
		return normWrite(err)
	}

	return nil
}

// GetOutgoingInvite retrieves an outgoing invite by id.
func (c *Core) GetOutgoingInvite(ctx context.Context, id string) (*store.OutgoingInvite, error) {
	var invite store.OutgoingInvite

	result := c.db.WithContext(ctx).First(&invite, "id = ?", id)
	if result.Error != nil {
		return nil, normNotFound(result.Error)
	}

	return &invite, nil
}

// GetOutgoingInviteByToken retrieves an outgoing invite by token.
func (c *Core) GetOutgoingInviteByToken(ctx context.Context, token string) (*store.OutgoingInvite, error) {
	var invite store.OutgoingInvite

	result := c.db.WithContext(ctx).First(&invite, "token = ?", token)
	if result.Error != nil {
		return nil, normNotFound(result.Error)
	}

	return &invite, nil
}

// UpdateOutgoingInvite updates an existing outgoing invite.
// Returns ErrNotFound when no row matches the ID (prevents silent upsert).
// The accepted identity (user id plus normalized host) coalesces with the
// stored row so a status-only write cannot erase it, and an accepted status
// without a complete identity is rejected. The raw accepted provider FQDN
// keeps replace semantics.
//
// The pre-read, validation, coalesce, and write run inside one serializable
// transaction so a concurrent writer cannot modify the row between the read
// and the write (TOCTOU). The Option B write-back is preserved exactly:
// only the coalesced AcceptedUserID and AcceptedProviderFQDNNormalized are
// written back before the update; the raw FQDN follows replace semantics
// and is not coalesced here.
func (c *Core) UpdateOutgoingInvite(ctx context.Context, invite *store.OutgoingInvite) error {
	if err := c.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var existing store.OutgoingInvite

		if err := tx.First(&existing, "id = ?", invite.ID).Error; err != nil {
			return normNotFound(err)
		}

		if err := invites.ValidateUpdateAcceptedIdentity(invite.Status,
			invite.AcceptedUserID, invite.AcceptedProviderFQDNNormalized,
			existing.AcceptedUserID, existing.AcceptedProviderFQDNNormalized); err != nil {
			return fmt.Errorf("store: validate update accepted identity: %w", err)
		}

		invite.AcceptedUserID, invite.AcceptedProviderFQDNNormalized = invites.CoalesceAcceptedIdentity(
			invite.AcceptedUserID, invite.AcceptedProviderFQDNNormalized,
			existing.AcceptedUserID, existing.AcceptedProviderFQDNNormalized)

		result := tx. //nolint:unqueryvet // intentional: select all columns for this GORM Updates chain; column list is intentionally open
				Model(&store.OutgoingInvite{}).
				Where("id = ?", invite.ID).
				Select("*").
				Updates(invite)
		if result.Error != nil {
			return normWrite(result.Error)
		}

		if result.RowsAffected == 0 {
			return store.ErrNotFound
		}

		return nil
	}); err != nil {
		return fmt.Errorf("store: apply outgoing invite update: %w", err)
	}

	return nil
}

// DeleteOutgoingInvite deletes an outgoing invite by id.
func (c *Core) DeleteOutgoingInvite(ctx context.Context, id string) error {
	result := c.db.WithContext(ctx).Delete(&store.OutgoingInvite{}, "id = ?", id)
	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		return store.ErrNotFound
	}

	return nil
}

// ListOutgoingInvites returns outgoing invites, optionally filtered by creator userID.
func (c *Core) ListOutgoingInvites(ctx context.Context, userID string) ([]*store.OutgoingInvite, error) {
	var invites []*store.OutgoingInvite

	query := c.db.WithContext(ctx)
	if userID != "" {
		query = query.Where("created_by_user_id = ?", userID)
	}

	if err := query.Find(&invites).Error; err != nil {
		return nil, err
	}

	return invites, nil
}

// ----------------------------------------------------------------------------
// IncomingInvite CRUD
// ----------------------------------------------------------------------------

// CreateIncomingInvite creates a new incoming invite.
func (c *Core) CreateIncomingInvite(ctx context.Context, invite *store.IncomingInvite) error {
	if err := invites.ValidateCreateInviteStatus(invite.Status, invite.SenderUserID, invite.SenderFQDNNormalized); err != nil {
		return fmt.Errorf("store: validate create invite status: %w", err)
	}

	if err := c.db.WithContext(ctx).Create(invite).Error; err != nil {
		return normWrite(err)
	}

	return nil
}

// GetIncomingInviteForRecipient retrieves an incoming invite by id scoped to a recipient.
func (c *Core) GetIncomingInviteForRecipient(ctx context.Context, id string, recipientUserID string) (*store.IncomingInvite, error) {
	var invite store.IncomingInvite

	result := c.db.WithContext(ctx).First(&invite, "id = ? AND recipient_user_id = ?", id, recipientUserID)
	if result.Error != nil {
		return nil, normNotFound(result.Error)
	}

	return &invite, nil
}

// GetIncomingInviteByToken retrieves an incoming invite by token scoped to a recipient.
func (c *Core) GetIncomingInviteByToken(ctx context.Context, token string, recipientUserID string) (*store.IncomingInvite, error) {
	var invite store.IncomingInvite

	result := c.db.WithContext(ctx).First(&invite, "token = ? AND recipient_user_id = ?", token, recipientUserID)
	if result.Error != nil {
		return nil, normNotFound(result.Error)
	}

	return &invite, nil
}

// UpdateIncomingInviteStatusForRecipient updates the status of an incoming invite
// scoped to a recipient, persisting the remote sender identity on acceptance when
// provided. Scope-defining fields (Token, RecipientUserID) are immutable after
// creation; sender identity coalesces with the stored row, and an accepted
// status without a complete identity is rejected. The recipient scope gate
// runs before identity validation so a wrong recipient stays ErrNotFound.
//
// The pre-read, validation, coalesce, and write run inside one serializable
// transaction so a concurrent writer cannot modify the row between the read
// and the write (TOCTOU). The Option B write-back is preserved exactly:
// only the coalesced SenderUserID and SenderFQDNNormalized are written back;
// no payload write occurs on partial-write paths.
func (c *Core) UpdateIncomingInviteStatusForRecipient(ctx context.Context, id string, recipientUserID string, status string, senderUserID string, senderFQDNNormalized string) error {
	if err := c.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var existing store.IncomingInvite

		if err := tx.First(&existing, "id = ? AND recipient_user_id = ?", id, recipientUserID).Error; err != nil {
			return normNotFound(err)
		}

		if err := invites.ValidateUpdateAcceptedIdentity(status, senderUserID, senderFQDNNormalized, existing.SenderUserID, existing.SenderFQDNNormalized); err != nil {
			return fmt.Errorf("store: validate update accepted identity: %w", err)
		}

		senderUserID, senderFQDNNormalized = invites.CoalesceAcceptedIdentity(
			senderUserID, senderFQDNNormalized, existing.SenderUserID, existing.SenderFQDNNormalized)

		updates := map[string]any{
			"status":     status,
			"updated_at": time.Now().Unix(),
		}

		if senderUserID != "" {
			updates["sender_user_id"] = senderUserID
		}

		if senderFQDNNormalized != "" {
			updates["sender_fqdn_normalized"] = senderFQDNNormalized
		}

		result := tx.
			Model(&store.IncomingInvite{}).
			Where("id = ? AND recipient_user_id = ?", id, recipientUserID).
			Updates(updates)
		if result.Error != nil {
			return result.Error
		}

		if result.RowsAffected == 0 {
			return store.ErrNotFound
		}

		return nil
	}); err != nil {
		return fmt.Errorf("store: apply incoming invite update: %w", err)
	}

	return nil
}

// DeleteIncomingInviteForRecipient deletes an incoming invite scoped to a recipient.
func (c *Core) DeleteIncomingInviteForRecipient(ctx context.Context, id string, recipientUserID string) error {
	result := c.db.WithContext(ctx).
		Where("id = ? AND recipient_user_id = ?", id, recipientUserID).
		Delete(&store.IncomingInvite{})
	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		return store.ErrNotFound
	}

	return nil
}

// ListIncomingInvites returns incoming invites for a recipient user.
func (c *Core) ListIncomingInvites(ctx context.Context, recipientUserID string) ([]*store.IncomingInvite, error) {
	var invites []*store.IncomingInvite
	if err := c.db.WithContext(ctx).Where("recipient_user_id = ?", recipientUserID).Find(&invites).Error; err != nil {
		return nil, err
	}

	return invites, nil
}

// ListAllIncomingInvites returns all incoming invites across all recipients.
func (c *Core) ListAllIncomingInvites(ctx context.Context) ([]*store.IncomingInvite, error) {
	var invites []*store.IncomingInvite
	if err := c.db.WithContext(ctx).Find(&invites).Error; err != nil {
		return nil, err
	}

	return invites, nil
}
