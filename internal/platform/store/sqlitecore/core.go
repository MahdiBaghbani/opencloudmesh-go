// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

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
	"os"
	"path/filepath"
	"time"

	gormsqlite "github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
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
	// Create the data dir up front so a fresh-CWD first boot works; matches
	// the JSON driver's Init behavior.
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("failed to create data dir: %w", err)
	}

	dbPath := filepath.Join(dataDir, "ocm.db")

	// busy_timeout lets a competing writer wait (up to 5s) for the database
	// lock instead of failing immediately with SQLITE_BUSY. _txlock=immediate
	// opens every write transaction with BEGIN IMMEDIATE, so the write lock is
	// taken at BEGIN instead of upgraded from a read lock mid-transaction: a
	// second writer blocks at its own BEGIN until the first transaction
	// commits, which eliminates the SHARED-to-RESERVED upgrade race that made
	// concurrent updates intermittently fail. Combined with wrapping the
	// read-then-write update paths in one transaction, the pre-read +
	// validate + coalesce + write is atomic: no other writer can commit
	// between the pre-read and the write.
	dsn := dbPath + "?_pragma=busy_timeout(5000)&_txlock=immediate"

	db, err := gorm.Open(gormsqlite.Open(dsn), &gorm.Config{
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

	if migrErr := validatorcore.MigrateModels(db); migrErr != nil {
		migrErr = fmt.Errorf("failed to migrate validator models: %w", migrErr)
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
		return fmt.Errorf("store: get sql db: %w", err)
	}

	if err := sqlDB.Close(); err != nil {
		return fmt.Errorf("store: close sql db: %w", err)
	}

	return nil
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
	result := c.db.WithContext(ctx). //nolint:unqueryvet // intentional: select all columns for this GORM Updates chain; column list is intentionally open
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

	result := c.db.WithContext(ctx).First(&share, "share_id = ? AND recipient_user_id = ?", shareID, recipientUserID)
	if result.Error != nil {
		return nil, normNotFound(result.Error)
	}

	return &share, nil
}

// GetIncomingShareByProviderKey retrieves an incoming share by sending server and providerID.
func (c *Core) GetIncomingShareByProviderKey(ctx context.Context, senderHost, providerID string) (*store.IncomingShare, error) {
	var share store.IncomingShare

	result := c.db.WithContext(ctx).First(&share, "sender_host = ? AND provider_id = ?", senderHost, providerID)
	if result.Error != nil {
		return nil, normNotFound(result.Error)
	}

	return &share, nil
}

// ListIncomingSharesByRecipient returns incoming shares for the given recipient user.
func (c *Core) ListIncomingSharesByRecipient(ctx context.Context, recipientUserID string) ([]*store.IncomingShare, error) {
	var shares []*store.IncomingShare
	if err := c.db.WithContext(ctx).Where("recipient_user_id = ?", recipientUserID).Find(&shares).Error; err != nil {
		return nil, err
	}

	return shares, nil
}

// UpdateIncomingShareStatusForRecipient updates the status of an incoming share scoped to a
// recipient. Only status and updated_at are written; other fields are not changed here.
func (c *Core) UpdateIncomingShareStatusForRecipient(ctx context.Context, shareID string, recipientUserID string, status string) error {
	result := c.db.WithContext(ctx).
		Model(&store.IncomingShare{}).
		Where("share_id = ? AND recipient_user_id = ?", shareID, recipientUserID).
		Updates(map[string]any{
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

// DeleteIncomingShareForRecipient deletes an incoming share scoped to a recipient.
func (c *Core) DeleteIncomingShareForRecipient(ctx context.Context, shareID string, recipientUserID string) error {
	result := c.db.WithContext(ctx).
		Where("share_id = ? AND recipient_user_id = ?", shareID, recipientUserID).
		Delete(&store.IncomingShare{})
	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		return store.ErrNotFound
	}

	return nil
}

// ListAllIncomingShares returns all incoming shares across all recipients.
func (c *Core) ListAllIncomingShares(ctx context.Context) ([]*store.IncomingShare, error) {
	var shares []*store.IncomingShare
	if err := c.db.WithContext(ctx).Find(&shares).Error; err != nil {
		return nil, err
	}

	return shares, nil
}
