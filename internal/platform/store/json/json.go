// Package json implements a JSON file-based persistence driver.
// It uses atomic writes (temp file + fsync + rename) and in-process locking.
package json

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
)

func init() {
	store.Register("json", NewDriver)
}

// Driver implements the store.Driver interface using JSON files.
type Driver struct {
	dataDir string
	mu      sync.RWMutex
	closed  bool

	// In-memory state loaded from JSON
	outgoingShares  map[string]*store.OutgoingShare  // keyed by providerId
	incomingShares  map[string]*store.IncomingShare  // keyed by shareId
	outgoingInvites map[string]*store.OutgoingInvite // keyed by id
	incomingInvites map[string]*store.IncomingInvite // keyed by id

	// Secondary indexes for outgoing shares
	webdavIndex  map[string]string // webdavId -> providerId
	shareIdIndex map[string]string // shareId -> providerId
	secretIndex  map[string]string // sharedSecret -> providerId

	// Secondary indexes for incoming shares
	providerIndex map[string]string // "sendingServer:providerId" -> shareId

	// Secondary indexes for invites
	outgoingInviteTokenIndex     map[string]string // token -> outgoing invite id
	incomingInviteTokenUserIndex map[string]string // "token\x00recipientUserId" -> incoming invite id
}

// NewDriver creates a new JSON driver instance.
func NewDriver(cfg *store.DriverConfig) (store.Driver, error) {
	if cfg.DataDir == "" {
		return nil, fmt.Errorf("data_dir is required for json driver")
	}

	return &Driver{
		dataDir:                      cfg.DataDir,
		outgoingShares:               make(map[string]*store.OutgoingShare),
		incomingShares:               make(map[string]*store.IncomingShare),
		outgoingInvites:              make(map[string]*store.OutgoingInvite),
		incomingInvites:              make(map[string]*store.IncomingInvite),
		webdavIndex:                  make(map[string]string),
		shareIdIndex:                 make(map[string]string),
		secretIndex:                  make(map[string]string),
		providerIndex:                make(map[string]string),
		outgoingInviteTokenIndex:     make(map[string]string),
		incomingInviteTokenUserIndex: make(map[string]string),
	}, nil
}

// Name returns the driver name.
func (d *Driver) Name() string {
	return "json"
}

// Init loads data from JSON files.
func (d *Driver) Init(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if err := os.MkdirAll(d.dataDir, 0700); err != nil {
		return fmt.Errorf("failed to create data dir: %w", err)
	}

	if err := d.loadFile(fileOutgoingShares, &d.outgoingShares); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to load outgoing shares: %w", err)
	}
	if err := d.loadFile(fileIncomingShares, &d.incomingShares); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to load incoming shares: %w", err)
	}
	if err := d.loadFile(fileOutgoingInvites, &d.outgoingInvites); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to load outgoing invites: %w", err)
	}
	if err := d.loadFile(fileIncomingInvites, &d.incomingInvites); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to load incoming invites: %w", err)
	}

	if err := d.rebuildIndexes(); err != nil {
		return fmt.Errorf("failed to rebuild indexes: %w", err)
	}

	return nil
}

// Close releases resources.
func (d *Driver) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = true
	return nil
}

// Compile-time interface checks
var _ store.Driver = (*Driver)(nil)
var _ store.OutgoingShareStore = (*Driver)(nil)
var _ store.IncomingShareStore = (*Driver)(nil)
var _ store.OutgoingInviteStore = (*Driver)(nil)
var _ store.IncomingInviteStore = (*Driver)(nil)
