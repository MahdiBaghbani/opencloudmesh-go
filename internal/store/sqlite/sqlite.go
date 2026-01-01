// Package sqlite implements a SQLite-based persistence driver using GORM.
package sqlite

import (
	"context"
	"fmt"
	"path/filepath"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/store"
)

func init() {
	store.Register("sqlite", NewDriver)
}

// Driver implements the store.Driver interface using SQLite via GORM.
type Driver struct {
	dataDir string
	db      *gorm.DB
}

// NewDriver creates a new SQLite driver instance.
func NewDriver(cfg *store.DriverConfig) (store.Driver, error) {
	if cfg.DataDir == "" {
		return nil, fmt.Errorf("data_dir is required for sqlite driver")
	}

	return &Driver{
		dataDir: cfg.DataDir,
	}, nil
}

// Name returns the driver name.
func (d *Driver) Name() string {
	return "sqlite"
}

// Init initializes the SQLite database and runs AutoMigrate.
func (d *Driver) Init(ctx context.Context) error {
	dbPath := filepath.Join(d.dataDir, "ocm.db")

	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	d.db = db

	// AutoMigrate creates/updates tables based on model structs
	if err := db.AutoMigrate(
		&store.OutgoingShare{},
		&store.IncomingShare{},
		&store.Invite{},
	); err != nil {
		return fmt.Errorf("failed to migrate database: %w", err)
	}

	return nil
}

// Close closes the database connection.
func (d *Driver) Close() error {
	if d.db == nil {
		return nil
	}
	sqlDB, err := d.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

// ShareStore implementation

// CreateOutgoingShare creates a new outgoing share.
func (d *Driver) CreateOutgoingShare(ctx context.Context, share *store.OutgoingShare) error {
	result := d.db.WithContext(ctx).Create(share)
	if result.Error != nil {
		return result.Error
	}
	return nil
}

// GetOutgoingShare retrieves an outgoing share by providerId.
func (d *Driver) GetOutgoingShare(ctx context.Context, providerId string) (*store.OutgoingShare, error) {
	var share store.OutgoingShare
	result := d.db.WithContext(ctx).First(&share, "provider_id = ?", providerId)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return nil, store.ErrNotFound
		}
		return nil, result.Error
	}
	return &share, nil
}

// GetOutgoingShareByWebDAVId retrieves an outgoing share by webdavId.
func (d *Driver) GetOutgoingShareByWebDAVId(ctx context.Context, webdavId string) (*store.OutgoingShare, error) {
	var share store.OutgoingShare
	result := d.db.WithContext(ctx).First(&share, "web_dav_id = ?", webdavId)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return nil, store.ErrNotFound
		}
		return nil, result.Error
	}
	return &share, nil
}

// UpdateOutgoingShare updates an existing outgoing share.
func (d *Driver) UpdateOutgoingShare(ctx context.Context, share *store.OutgoingShare) error {
	result := d.db.WithContext(ctx).Save(share)
	return result.Error
}

// DeleteOutgoingShare deletes an outgoing share.
func (d *Driver) DeleteOutgoingShare(ctx context.Context, providerId string) error {
	result := d.db.WithContext(ctx).Delete(&store.OutgoingShare{}, "provider_id = ?", providerId)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return store.ErrNotFound
	}
	return nil
}

// ListOutgoingShares returns all outgoing shares.
func (d *Driver) ListOutgoingShares(ctx context.Context) ([]*store.OutgoingShare, error) {
	var shares []*store.OutgoingShare
	result := d.db.WithContext(ctx).Find(&shares)
	if result.Error != nil {
		return nil, result.Error
	}
	return shares, nil
}

// CreateIncomingShare creates a new incoming share.
func (d *Driver) CreateIncomingShare(ctx context.Context, share *store.IncomingShare) error {
	result := d.db.WithContext(ctx).Create(share)
	return result.Error
}

// GetIncomingShare retrieves an incoming share by shareId.
func (d *Driver) GetIncomingShare(ctx context.Context, shareId string) (*store.IncomingShare, error) {
	var share store.IncomingShare
	result := d.db.WithContext(ctx).First(&share, "share_id = ?", shareId)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return nil, store.ErrNotFound
		}
		return nil, result.Error
	}
	return &share, nil
}

// GetIncomingShareByProviderKey retrieves an incoming share by sending server and providerId.
func (d *Driver) GetIncomingShareByProviderKey(ctx context.Context, sendingServer, providerId string) (*store.IncomingShare, error) {
	var share store.IncomingShare
	result := d.db.WithContext(ctx).First(&share, "sending_server = ? AND provider_id = ?", sendingServer, providerId)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return nil, store.ErrNotFound
		}
		return nil, result.Error
	}
	return &share, nil
}

// UpdateIncomingShare updates an existing incoming share.
func (d *Driver) UpdateIncomingShare(ctx context.Context, share *store.IncomingShare) error {
	result := d.db.WithContext(ctx).Save(share)
	return result.Error
}

// DeleteIncomingShare deletes an incoming share.
func (d *Driver) DeleteIncomingShare(ctx context.Context, shareId string) error {
	result := d.db.WithContext(ctx).Delete(&store.IncomingShare{}, "share_id = ?", shareId)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return store.ErrNotFound
	}
	return nil
}

// ListIncomingShares returns incoming shares for a user.
func (d *Driver) ListIncomingShares(ctx context.Context, userId string) ([]*store.IncomingShare, error) {
	var shares []*store.IncomingShare
	query := d.db.WithContext(ctx)
	if userId != "" {
		query = query.Where("user_id = ?", userId)
	}
	result := query.Find(&shares)
	if result.Error != nil {
		return nil, result.Error
	}
	return shares, nil
}

// Compile-time interface checks
var _ store.Driver = (*Driver)(nil)
var _ store.ShareStore = (*Driver)(nil)
