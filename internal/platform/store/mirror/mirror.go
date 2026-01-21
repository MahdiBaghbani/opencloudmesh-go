// Package mirror implements a SQLite + JSON mirror persistence driver.
// SQLite is the source of truth; JSON is a one-way export for supervisor visibility.
// The program MUST NOT read JSON as input.
package mirror

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
)

func init() {
	store.Register("mirror", NewDriver)
}

// Driver implements the store.Driver interface with SQLite + JSON mirror.
type Driver struct {
	dataDir       string
	db            *gorm.DB
	mirrorCfg     store.MirrorConfig
	secretsLookup map[string]bool // quick lookup for allowed secret scopes
	mu            sync.Mutex      // protects JSON export operations
}

// NewDriver creates a new mirror driver instance.
func NewDriver(cfg *store.DriverConfig) (store.Driver, error) {
	if cfg.DataDir == "" {
		return nil, fmt.Errorf("data_dir is required for mirror driver")
	}

	// Build secrets scope lookup
	lookup := make(map[string]bool)
	for _, scope := range cfg.Mirror.SecretsScope {
		lookup[scope] = true
	}

	return &Driver{
		dataDir:       cfg.DataDir,
		mirrorCfg:     cfg.Mirror,
		secretsLookup: lookup,
	}, nil
}

// Name returns the driver name.
func (d *Driver) Name() string {
	return "mirror"
}

// Init initializes the SQLite database and exports initial state to JSON.
func (d *Driver) Init(ctx context.Context) error {
	dbPath := filepath.Join(d.dataDir, "ocm.db")
	mirrorDir := filepath.Join(d.dataDir, "mirror")

	// Create mirror directory
	if err := os.MkdirAll(mirrorDir, 0700); err != nil {
		return fmt.Errorf("failed to create mirror dir: %w", err)
	}

	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	d.db = db

	// AutoMigrate
	if err := db.AutoMigrate(
		&store.OutgoingShare{},
		&store.IncomingShare{},
		&store.Invite{},
	); err != nil {
		return fmt.Errorf("failed to migrate database: %w", err)
	}

	// Initial mirror export
	if err := d.exportAll(ctx); err != nil {
		return fmt.Errorf("failed to export mirror: %w", err)
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

// exportAll exports all data to JSON files with appropriate redaction.
func (d *Driver) exportAll(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if err := d.exportOutgoingShares(ctx); err != nil {
		return err
	}
	if err := d.exportIncomingShares(ctx); err != nil {
		return err
	}
	if err := d.exportInvites(ctx); err != nil {
		return err
	}
	return nil
}

// shouldIncludeSecret checks if a secret type should be included in export.
func (d *Driver) shouldIncludeSecret(scope string) bool {
	if !d.mirrorCfg.IncludeSecrets {
		return false
	}
	return d.secretsLookup[scope]
}

// exportOutgoingShares exports outgoing shares to JSON with optional redaction.
func (d *Driver) exportOutgoingShares(ctx context.Context) error {
	var shares []*store.OutgoingShare
	if err := d.db.WithContext(ctx).Find(&shares).Error; err != nil {
		return err
	}

	// Redact secrets if not allowed
	if !d.shouldIncludeSecret("webdav_shared_secrets") {
		for _, share := range shares {
			share.SharedSecret = ""
		}
	}

	return d.writeJSON("outgoing_shares.json", shares)
}

// exportIncomingShares exports incoming shares to JSON with optional redaction.
func (d *Driver) exportIncomingShares(ctx context.Context) error {
	var shares []*store.IncomingShare
	if err := d.db.WithContext(ctx).Find(&shares).Error; err != nil {
		return err
	}

	// Redact secrets if not allowed
	if !d.shouldIncludeSecret("webdav_shared_secrets") {
		for _, share := range shares {
			share.SharedSecret = ""
		}
	}

	return d.writeJSON("incoming_shares.json", shares)
}

// exportInvites exports invites to JSON.
func (d *Driver) exportInvites(ctx context.Context) error {
	var invites []*store.Invite
	if err := d.db.WithContext(ctx).Find(&invites).Error; err != nil {
		return err
	}
	return d.writeJSON("invites.json", invites)
}

// writeJSON atomically writes data to a JSON file in the mirror directory.
func (d *Driver) writeJSON(filename string, data interface{}) error {
	mirrorDir := filepath.Join(d.dataDir, "mirror")
	path := filepath.Join(mirrorDir, filename)
	tempPath := path + ".tmp"

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	f, err := os.OpenFile(tempPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}

	if _, err := f.Write(jsonData); err != nil {
		f.Close()
		os.Remove(tempPath)
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tempPath)
		return fmt.Errorf("failed to sync temp file: %w", err)
	}

	if err := f.Close(); err != nil {
		os.Remove(tempPath)
		return fmt.Errorf("failed to close temp file: %w", err)
	}

	if err := os.Rename(tempPath, path); err != nil {
		os.Remove(tempPath)
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	return nil
}

// ShareStore implementation - delegates to SQLite and exports after writes

// CreateOutgoingShare creates a new outgoing share.
func (d *Driver) CreateOutgoingShare(ctx context.Context, share *store.OutgoingShare) error {
	if err := d.db.WithContext(ctx).Create(share).Error; err != nil {
		return err
	}
	return d.exportOutgoingShares(ctx)
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
	if err := d.db.WithContext(ctx).Save(share).Error; err != nil {
		return err
	}
	return d.exportOutgoingShares(ctx)
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
	return d.exportOutgoingShares(ctx)
}

// ListOutgoingShares returns all outgoing shares.
func (d *Driver) ListOutgoingShares(ctx context.Context) ([]*store.OutgoingShare, error) {
	var shares []*store.OutgoingShare
	if err := d.db.WithContext(ctx).Find(&shares).Error; err != nil {
		return nil, err
	}
	return shares, nil
}

// CreateIncomingShare creates a new incoming share.
func (d *Driver) CreateIncomingShare(ctx context.Context, share *store.IncomingShare) error {
	if err := d.db.WithContext(ctx).Create(share).Error; err != nil {
		return err
	}
	return d.exportIncomingShares(ctx)
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
	if err := d.db.WithContext(ctx).Save(share).Error; err != nil {
		return err
	}
	return d.exportIncomingShares(ctx)
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
	return d.exportIncomingShares(ctx)
}

// ListIncomingShares returns incoming shares for a user.
func (d *Driver) ListIncomingShares(ctx context.Context, userId string) ([]*store.IncomingShare, error) {
	var shares []*store.IncomingShare
	query := d.db.WithContext(ctx)
	if userId != "" {
		query = query.Where("user_id = ?", userId)
	}
	if err := query.Find(&shares).Error; err != nil {
		return nil, err
	}
	return shares, nil
}

// Compile-time interface checks
var _ store.Driver = (*Driver)(nil)
var _ store.ShareStore = (*Driver)(nil)
