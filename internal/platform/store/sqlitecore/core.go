// Package sqlitecore is the private shared SQLite/GORM persistence engine used
// by the sqlite and mirror drivers. It owns DB lifecycle (open/migrate/close)
// and the full four-surface CRUD layer. Driver-specific behaviour (JSON export,
// secret redaction) lives in the drivers themselves and is not part of this
// package.
package sqlitecore

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	gormsqlite "gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
)

// Core holds an open GORM/SQLite handle and provides the full four-surface
// CRUD layer. Lifecycle: Open -> CRUD -> Close.
type Core struct {
	db *gorm.DB
}

// Open opens (or creates) ocm.db under dataDir, runs AutoMigrate for all four
// persistence models, and returns a ready Core. The caller owns the Core and
// must call Close when done.
func Open(dataDir string) (*Core, error) {
	dbPath := filepath.Join(dataDir, "ocm.db")

	db, err := gorm.Open(gormsqlite.Open(dbPath), &gorm.Config{
		Logger:         logger.Default.LogMode(logger.Silent),
		TranslateError: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if migrErr := db.AutoMigrate(
		&store.OutgoingShare{},
		&store.IncomingShare{},
		&store.OutgoingInvite{},
		&store.IncomingInvite{},
	); migrErr != nil {
		migrErr = fmt.Errorf("failed to migrate database: %w", migrErr)
		if sqlDB, dbErr := db.DB(); dbErr != nil {
			return nil, errors.Join(migrErr, dbErr)
		} else if closeErr := sqlDB.Close(); closeErr != nil {
			return nil, errors.Join(migrErr, closeErr)
		}

		return nil, migrErr
	}

	return &Core{db: db}, nil
}

// Close releases the underlying database connection. Safe to call on a nil Core.
func (c *Core) Close() error {
	if c == nil || c.db == nil {
		return nil
	}

	sqlDB, err := c.db.DB()
	if err != nil {
		return err
	}

	return sqlDB.Close()
}

// normNotFound maps gorm.ErrRecordNotFound to store.ErrNotFound and passes
// all other errors through unchanged.
func normNotFound(err error) error {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return store.ErrNotFound
	}

	return err
}

// normWrite maps gorm.ErrDuplicatedKey to store.ErrAlreadyExists and passes
// all other errors through unchanged.
func normWrite(err error) error {
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return store.ErrAlreadyExists
	}

	return err
}

// ----------------------------------------------------------------------------
// OutgoingShare CRUD
// ----------------------------------------------------------------------------

// CreateOutgoingShare creates a new outgoing share.
func (c *Core) CreateOutgoingShare(ctx context.Context, share *store.OutgoingShare) error {
	if err := c.db.WithContext(ctx).Create(share).Error; err != nil {
		return normWrite(err)
	}

	return nil
}

// GetOutgoingShareByID retrieves an outgoing share by its local share id.
func (c *Core) GetOutgoingShareByID(ctx context.Context, shareID string) (*store.OutgoingShare, error) {
	var share store.OutgoingShare

	result := c.db.WithContext(ctx).First(&share, "share_id = ?", shareID)
	if result.Error != nil {
		return nil, normNotFound(result.Error)
	}

	return &share, nil
}

// GetOutgoingShare retrieves an outgoing share by providerID.
func (c *Core) GetOutgoingShare(ctx context.Context, providerID string) (*store.OutgoingShare, error) {
	var share store.OutgoingShare

	result := c.db.WithContext(ctx).First(&share, "provider_id = ?", providerID)
	if result.Error != nil {
		return nil, normNotFound(result.Error)
	}

	return &share, nil
}

// GetOutgoingShareByWebDAVID retrieves an outgoing share by webdavID.
func (c *Core) GetOutgoingShareByWebDAVID(ctx context.Context, webdavID string) (*store.OutgoingShare, error) {
	var share store.OutgoingShare

	result := c.db.WithContext(ctx).First(&share, "web_dav_id = ?", webdavID)
	if result.Error != nil {
		return nil, normNotFound(result.Error)
	}

	return &share, nil
}

// GetOutgoingShareBySharedSecret retrieves an outgoing share by shared secret.
// Empty shared secret is not a valid lookup key; multiple rows may have an
// empty secret, so returning one of them arbitrarily would violate singular-key
// semantics. Return ErrNotFound immediately to match JSON backend behaviour.
func (c *Core) GetOutgoingShareBySharedSecret(ctx context.Context, sharedSecret string) (*store.OutgoingShare, error) {
	if sharedSecret == "" {
		return nil, store.ErrNotFound
	}

	var share store.OutgoingShare

	result := c.db.WithContext(ctx).First(&share, "shared_secret = ?", sharedSecret)
	if result.Error != nil {
		return nil, normNotFound(result.Error)
	}

	return &share, nil
}

// UpdateOutgoingShare updates an existing outgoing share.
// Returns ErrNotFound when no row matches the ProviderID (prevents silent upsert).
// Uses a single UPDATE statement so there is no TOCTOU race between existence
// check and write.
func (c *Core) UpdateOutgoingShare(ctx context.Context, share *store.OutgoingShare) error {
	result := c.db.WithContext(ctx).
		Model(&store.OutgoingShare{}).
		Where("provider_id = ?", share.ProviderID).
		Select("*").
		Updates(share)
	if result.Error != nil {
		return normWrite(result.Error)
	}

	if result.RowsAffected == 0 {
		return store.ErrNotFound
	}

	return nil
}

// DeleteOutgoingShare deletes an outgoing share by providerID.
func (c *Core) DeleteOutgoingShare(ctx context.Context, providerID string) error {
	result := c.db.WithContext(ctx).Delete(&store.OutgoingShare{}, "provider_id = ?", providerID)
	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		return store.ErrNotFound
	}

	return nil
}

// ListOutgoingShares returns all outgoing shares.
func (c *Core) ListOutgoingShares(ctx context.Context) ([]*store.OutgoingShare, error) {
	var shares []*store.OutgoingShare
	if err := c.db.WithContext(ctx).Find(&shares).Error; err != nil {
		return nil, err
	}

	return shares, nil
}

// ----------------------------------------------------------------------------
// IncomingShare CRUD
// ----------------------------------------------------------------------------

// CreateIncomingShare creates a new incoming share.
func (c *Core) CreateIncomingShare(ctx context.Context, share *store.IncomingShare) error {
	if err := c.db.WithContext(ctx).Create(share).Error; err != nil {
		return normWrite(err)
	}

	return nil
}

// GetIncomingShareByIDForRecipient retrieves an incoming share by shareID scoped to a recipient.
func (c *Core) GetIncomingShareByIDForRecipient(ctx context.Context, shareID string, recipientUserID string) (*store.IncomingShare, error) {
	var share store.IncomingShare

	result := c.db.WithContext(ctx).First(&share, "share_id = ? AND user_id = ?", shareID, recipientUserID)
	if result.Error != nil {
		return nil, normNotFound(result.Error)
	}

	return &share, nil
}

// GetIncomingShareByProviderKey retrieves an incoming share by sending server and providerID.
func (c *Core) GetIncomingShareByProviderKey(ctx context.Context, sendingServer, providerID string) (*store.IncomingShare, error) {
	var share store.IncomingShare

	result := c.db.WithContext(ctx).First(&share, "sending_server = ? AND provider_id = ?", sendingServer, providerID)
	if result.Error != nil {
		return nil, normNotFound(result.Error)
	}

	return &share, nil
}

// ListIncomingSharesByRecipient returns incoming shares for the given recipient user.
func (c *Core) ListIncomingSharesByRecipient(ctx context.Context, recipientUserID string) ([]*store.IncomingShare, error) {
	var shares []*store.IncomingShare
	if err := c.db.WithContext(ctx).Where("user_id = ?", recipientUserID).Find(&shares).Error; err != nil {
		return nil, err
	}

	return shares, nil
}

// UpdateIncomingShareStatusForRecipient updates the state of an incoming share scoped to a
// recipient. Only state and updated_at are written; other fields are not changed here.
func (c *Core) UpdateIncomingShareStatusForRecipient(ctx context.Context, shareID string, recipientUserID string, state string) error {
	result := c.db.WithContext(ctx).
		Model(&store.IncomingShare{}).
		Where("share_id = ? AND user_id = ?", shareID, recipientUserID).
		Updates(map[string]interface{}{
			"state":      state,
			"updated_at": time.Now().Unix(),
		})
	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		return store.ErrNotFound
	}

	return nil
}

// DeleteIncomingShareForRecipient deletes an incoming share scoped to a recipient.
func (c *Core) DeleteIncomingShareForRecipient(ctx context.Context, shareID string, recipientUserID string) error {
	result := c.db.WithContext(ctx).
		Where("share_id = ? AND user_id = ?", shareID, recipientUserID).
		Delete(&store.IncomingShare{})
	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		return store.ErrNotFound
	}

	return nil
}

// ----------------------------------------------------------------------------
// OutgoingInvite CRUD
// ----------------------------------------------------------------------------

// CreateOutgoingInvite creates a new outgoing invite.
func (c *Core) CreateOutgoingInvite(ctx context.Context, invite *store.OutgoingInvite) error {
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
// Uses a single UPDATE statement so there is no TOCTOU race between existence
// check and write.
func (c *Core) UpdateOutgoingInvite(ctx context.Context, invite *store.OutgoingInvite) error {
	result := c.db.WithContext(ctx).
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

// UpdateIncomingInviteStatusForRecipient updates only the status of an incoming invite
// scoped to a recipient. Scope-defining fields (Token, RecipientUserID) are immutable
// after creation; only Status and UpdatedAt are changed.
func (c *Core) UpdateIncomingInviteStatusForRecipient(ctx context.Context, id string, recipientUserID string, status string) error {
	result := c.db.WithContext(ctx).
		Model(&store.IncomingInvite{}).
		Where("id = ? AND recipient_user_id = ?", id, recipientUserID).
		Updates(map[string]interface{}{
			"status":     status,
			"updated_at": time.Now().Unix(),
		})
	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		return store.ErrNotFound
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

// ListAllIncomingShares returns all incoming shares across all recipients.
func (c *Core) ListAllIncomingShares(ctx context.Context) ([]*store.IncomingShare, error) {
	var shares []*store.IncomingShare
	if err := c.db.WithContext(ctx).Find(&shares).Error; err != nil {
		return nil, err
	}

	return shares, nil
}

// ListAllIncomingInvites returns all incoming invites across all recipients.
func (c *Core) ListAllIncomingInvites(ctx context.Context) ([]*store.IncomingInvite, error) {
	var invites []*store.IncomingInvite
	if err := c.db.WithContext(ctx).Find(&invites).Error; err != nil {
		return nil, err
	}

	return invites, nil
}
