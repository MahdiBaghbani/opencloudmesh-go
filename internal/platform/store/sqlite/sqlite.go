// Package sqlite implements a SQLite-based persistence driver using GORM.
// It is a thin wrapper over the shared sqlitecore.Core engine.
package sqlite

import (
	"context"
	"fmt"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/sqlitecore"
)

func init() {
	store.Register("sqlite", NewDriver)
}

// Driver implements the store.Driver interface using the shared SQLite core.
// It implements all four persistence surfaces: OutgoingShareStore,
// IncomingShareStore, OutgoingInviteStore, and IncomingInviteStore.
type Driver struct {
	dataDir string
	core    *sqlitecore.Core
}

// NewDriver creates a new SQLite driver instance.
func NewDriver(cfg *store.DriverConfig) (store.Driver, error) {
	if cfg.DataDir == "" {
		return nil, fmt.Errorf("data_dir is required for sqlite driver")
	}
	return &Driver{dataDir: cfg.DataDir}, nil
}

// Name returns the driver name.
func (d *Driver) Name() string {
	return "sqlite"
}

// Init opens the SQLite database and runs AutoMigrate via the shared core.
func (d *Driver) Init(ctx context.Context) error {
	core, err := sqlitecore.Open(d.dataDir)
	if err != nil {
		return err
	}
	d.core = core
	return nil
}

// Close closes the database connection. Safe to call before Init.
func (d *Driver) Close() error {
	return d.core.Close()
}

// OutgoingShareStore implementation

func (d *Driver) CreateOutgoingShare(ctx context.Context, share *store.OutgoingShare) error {
	return d.core.CreateOutgoingShare(ctx, share)
}

func (d *Driver) GetOutgoingShareByID(ctx context.Context, shareId string) (*store.OutgoingShare, error) {
	return d.core.GetOutgoingShareByID(ctx, shareId)
}

func (d *Driver) GetOutgoingShare(ctx context.Context, providerId string) (*store.OutgoingShare, error) {
	return d.core.GetOutgoingShare(ctx, providerId)
}

func (d *Driver) GetOutgoingShareByWebDAVId(ctx context.Context, webdavId string) (*store.OutgoingShare, error) {
	return d.core.GetOutgoingShareByWebDAVId(ctx, webdavId)
}

func (d *Driver) GetOutgoingShareBySharedSecret(ctx context.Context, sharedSecret string) (*store.OutgoingShare, error) {
	return d.core.GetOutgoingShareBySharedSecret(ctx, sharedSecret)
}

func (d *Driver) UpdateOutgoingShare(ctx context.Context, share *store.OutgoingShare) error {
	return d.core.UpdateOutgoingShare(ctx, share)
}

func (d *Driver) DeleteOutgoingShare(ctx context.Context, providerId string) error {
	return d.core.DeleteOutgoingShare(ctx, providerId)
}

func (d *Driver) ListOutgoingShares(ctx context.Context) ([]*store.OutgoingShare, error) {
	return d.core.ListOutgoingShares(ctx)
}

// IncomingShareStore implementation

func (d *Driver) CreateIncomingShare(ctx context.Context, share *store.IncomingShare) error {
	return d.core.CreateIncomingShare(ctx, share)
}

func (d *Driver) GetIncomingShareByIDForRecipient(ctx context.Context, shareId string, recipientUserId string) (*store.IncomingShare, error) {
	return d.core.GetIncomingShareByIDForRecipient(ctx, shareId, recipientUserId)
}

func (d *Driver) GetIncomingShareByProviderKey(ctx context.Context, sendingServer, providerId string) (*store.IncomingShare, error) {
	return d.core.GetIncomingShareByProviderKey(ctx, sendingServer, providerId)
}

func (d *Driver) ListIncomingSharesByRecipient(ctx context.Context, recipientUserId string) ([]*store.IncomingShare, error) {
	return d.core.ListIncomingSharesByRecipient(ctx, recipientUserId)
}

func (d *Driver) UpdateIncomingShareStatusForRecipient(ctx context.Context, shareId string, recipientUserId string, state string) error {
	return d.core.UpdateIncomingShareStatusForRecipient(ctx, shareId, recipientUserId, state)
}

func (d *Driver) DeleteIncomingShareForRecipient(ctx context.Context, shareId string, recipientUserId string) error {
	return d.core.DeleteIncomingShareForRecipient(ctx, shareId, recipientUserId)
}

// OutgoingInviteStore implementation

func (d *Driver) CreateOutgoingInvite(ctx context.Context, invite *store.OutgoingInvite) error {
	return d.core.CreateOutgoingInvite(ctx, invite)
}

func (d *Driver) GetOutgoingInvite(ctx context.Context, id string) (*store.OutgoingInvite, error) {
	return d.core.GetOutgoingInvite(ctx, id)
}

func (d *Driver) GetOutgoingInviteByToken(ctx context.Context, token string) (*store.OutgoingInvite, error) {
	return d.core.GetOutgoingInviteByToken(ctx, token)
}

func (d *Driver) UpdateOutgoingInvite(ctx context.Context, invite *store.OutgoingInvite) error {
	return d.core.UpdateOutgoingInvite(ctx, invite)
}

func (d *Driver) DeleteOutgoingInvite(ctx context.Context, id string) error {
	return d.core.DeleteOutgoingInvite(ctx, id)
}

func (d *Driver) ListOutgoingInvites(ctx context.Context, userId string) ([]*store.OutgoingInvite, error) {
	return d.core.ListOutgoingInvites(ctx, userId)
}

// IncomingInviteStore implementation

func (d *Driver) CreateIncomingInvite(ctx context.Context, invite *store.IncomingInvite) error {
	return d.core.CreateIncomingInvite(ctx, invite)
}

func (d *Driver) GetIncomingInviteForRecipient(ctx context.Context, id string, recipientUserId string) (*store.IncomingInvite, error) {
	return d.core.GetIncomingInviteForRecipient(ctx, id, recipientUserId)
}

func (d *Driver) GetIncomingInviteByToken(ctx context.Context, token string, recipientUserId string) (*store.IncomingInvite, error) {
	return d.core.GetIncomingInviteByToken(ctx, token, recipientUserId)
}

func (d *Driver) UpdateIncomingInviteStatusForRecipient(ctx context.Context, id string, recipientUserId string, status string) error {
	return d.core.UpdateIncomingInviteStatusForRecipient(ctx, id, recipientUserId, status)
}

func (d *Driver) DeleteIncomingInviteForRecipient(ctx context.Context, id string, recipientUserId string) error {
	return d.core.DeleteIncomingInviteForRecipient(ctx, id, recipientUserId)
}

func (d *Driver) ListIncomingInvites(ctx context.Context, recipientUserId string) ([]*store.IncomingInvite, error) {
	return d.core.ListIncomingInvites(ctx, recipientUserId)
}

// Compile-time interface checks
var _ store.Driver = (*Driver)(nil)
var _ store.OutgoingShareStore = (*Driver)(nil)
var _ store.IncomingShareStore = (*Driver)(nil)
var _ store.OutgoingInviteStore = (*Driver)(nil)
var _ store.IncomingInviteStore = (*Driver)(nil)
