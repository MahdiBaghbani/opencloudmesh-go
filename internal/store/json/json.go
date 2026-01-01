// Package json implements a JSON file-based persistence driver.
// It uses atomic writes (temp file + fsync + rename) and in-process locking.
package json

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/store"
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
	outgoingShares map[string]*store.OutgoingShare // keyed by providerId
	incomingShares map[string]*store.IncomingShare // keyed by shareId
	invites        map[string]*store.Invite        // keyed by token

	// Secondary indexes
	webdavIndex   map[string]string // webdavId -> providerId
	providerIndex map[string]string // "sendingServer:providerId" -> shareId
}

// NewDriver creates a new JSON driver instance.
func NewDriver(cfg *store.DriverConfig) (store.Driver, error) {
	if cfg.DataDir == "" {
		return nil, fmt.Errorf("data_dir is required for json driver")
	}

	return &Driver{
		dataDir:        cfg.DataDir,
		outgoingShares: make(map[string]*store.OutgoingShare),
		incomingShares: make(map[string]*store.IncomingShare),
		invites:        make(map[string]*store.Invite),
		webdavIndex:    make(map[string]string),
		providerIndex:  make(map[string]string),
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

	// Create data directory if it doesn't exist
	if err := os.MkdirAll(d.dataDir, 0700); err != nil {
		return fmt.Errorf("failed to create data dir: %w", err)
	}

	// Load each data file
	if err := d.loadFile("outgoing_shares.json", &d.outgoingShares); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to load outgoing shares: %w", err)
	}
	if err := d.loadFile("incoming_shares.json", &d.incomingShares); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to load incoming shares: %w", err)
	}
	if err := d.loadFile("invites.json", &d.invites); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to load invites: %w", err)
	}

	// Rebuild indexes
	d.rebuildIndexes()

	return nil
}

// Close releases resources.
func (d *Driver) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = true
	return nil
}

// loadFile loads a JSON file into the target map.
func (d *Driver) loadFile(filename string, target interface{}) error {
	path := filepath.Join(d.dataDir, filename)
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, target)
}

// saveFile atomically writes data to a JSON file.
// Pattern: write to temp file, fsync, rename.
func (d *Driver) saveFile(filename string, data interface{}) error {
	path := filepath.Join(d.dataDir, filename)
	tempPath := path + ".tmp"

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	// Write to temp file
	f, err := os.OpenFile(tempPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}

	if _, err := f.Write(jsonData); err != nil {
		f.Close()
		os.Remove(tempPath)
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	// Fsync to ensure data is on disk
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tempPath)
		return fmt.Errorf("failed to sync temp file: %w", err)
	}

	if err := f.Close(); err != nil {
		os.Remove(tempPath)
		return fmt.Errorf("failed to close temp file: %w", err)
	}

	// Atomic rename
	if err := os.Rename(tempPath, path); err != nil {
		os.Remove(tempPath)
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	return nil
}

// rebuildIndexes rebuilds secondary indexes from primary data.
func (d *Driver) rebuildIndexes() {
	d.webdavIndex = make(map[string]string)
	d.providerIndex = make(map[string]string)

	for providerId, share := range d.outgoingShares {
		if share.WebDAVId != "" {
			d.webdavIndex[share.WebDAVId] = providerId
		}
	}

	for shareId, share := range d.incomingShares {
		key := share.SendingServer + ":" + share.ProviderId
		d.providerIndex[key] = shareId
	}
}

// providerKey creates a lookup key for incoming shares.
func providerKey(sendingServer, providerId string) string {
	return sendingServer + ":" + providerId
}

// ShareStore implementation

// CreateOutgoingShare creates a new outgoing share.
func (d *Driver) CreateOutgoingShare(ctx context.Context, share *store.OutgoingShare) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return store.ErrClosed
	}

	if _, exists := d.outgoingShares[share.ProviderId]; exists {
		return store.ErrAlreadyExists
	}

	d.outgoingShares[share.ProviderId] = share
	if share.WebDAVId != "" {
		d.webdavIndex[share.WebDAVId] = share.ProviderId
	}

	return d.saveFile("outgoing_shares.json", d.outgoingShares)
}

// GetOutgoingShare retrieves an outgoing share by providerId.
func (d *Driver) GetOutgoingShare(ctx context.Context, providerId string) (*store.OutgoingShare, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.closed {
		return nil, store.ErrClosed
	}

	share, ok := d.outgoingShares[providerId]
	if !ok {
		return nil, store.ErrNotFound
	}
	return share, nil
}

// GetOutgoingShareByWebDAVId retrieves an outgoing share by webdavId.
func (d *Driver) GetOutgoingShareByWebDAVId(ctx context.Context, webdavId string) (*store.OutgoingShare, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.closed {
		return nil, store.ErrClosed
	}

	providerId, ok := d.webdavIndex[webdavId]
	if !ok {
		return nil, store.ErrNotFound
	}

	share, ok := d.outgoingShares[providerId]
	if !ok {
		return nil, store.ErrNotFound
	}
	return share, nil
}

// UpdateOutgoingShare updates an existing outgoing share.
func (d *Driver) UpdateOutgoingShare(ctx context.Context, share *store.OutgoingShare) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return store.ErrClosed
	}

	if _, exists := d.outgoingShares[share.ProviderId]; !exists {
		return store.ErrNotFound
	}

	d.outgoingShares[share.ProviderId] = share
	if share.WebDAVId != "" {
		d.webdavIndex[share.WebDAVId] = share.ProviderId
	}

	return d.saveFile("outgoing_shares.json", d.outgoingShares)
}

// DeleteOutgoingShare deletes an outgoing share.
func (d *Driver) DeleteOutgoingShare(ctx context.Context, providerId string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return store.ErrClosed
	}

	share, exists := d.outgoingShares[providerId]
	if !exists {
		return store.ErrNotFound
	}

	if share.WebDAVId != "" {
		delete(d.webdavIndex, share.WebDAVId)
	}
	delete(d.outgoingShares, providerId)

	return d.saveFile("outgoing_shares.json", d.outgoingShares)
}

// ListOutgoingShares returns all outgoing shares.
func (d *Driver) ListOutgoingShares(ctx context.Context) ([]*store.OutgoingShare, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.closed {
		return nil, store.ErrClosed
	}

	shares := make([]*store.OutgoingShare, 0, len(d.outgoingShares))
	for _, share := range d.outgoingShares {
		shares = append(shares, share)
	}
	return shares, nil
}

// CreateIncomingShare creates a new incoming share.
func (d *Driver) CreateIncomingShare(ctx context.Context, share *store.IncomingShare) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return store.ErrClosed
	}

	if _, exists := d.incomingShares[share.ShareId]; exists {
		return store.ErrAlreadyExists
	}

	d.incomingShares[share.ShareId] = share
	d.providerIndex[providerKey(share.SendingServer, share.ProviderId)] = share.ShareId

	return d.saveFile("incoming_shares.json", d.incomingShares)
}

// GetIncomingShare retrieves an incoming share by shareId.
func (d *Driver) GetIncomingShare(ctx context.Context, shareId string) (*store.IncomingShare, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.closed {
		return nil, store.ErrClosed
	}

	share, ok := d.incomingShares[shareId]
	if !ok {
		return nil, store.ErrNotFound
	}
	return share, nil
}

// GetIncomingShareByProviderKey retrieves an incoming share by sending server and providerId.
func (d *Driver) GetIncomingShareByProviderKey(ctx context.Context, sendingServer, providerId string) (*store.IncomingShare, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.closed {
		return nil, store.ErrClosed
	}

	shareId, ok := d.providerIndex[providerKey(sendingServer, providerId)]
	if !ok {
		return nil, store.ErrNotFound
	}

	share, ok := d.incomingShares[shareId]
	if !ok {
		return nil, store.ErrNotFound
	}
	return share, nil
}

// UpdateIncomingShare updates an existing incoming share.
func (d *Driver) UpdateIncomingShare(ctx context.Context, share *store.IncomingShare) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return store.ErrClosed
	}

	if _, exists := d.incomingShares[share.ShareId]; !exists {
		return store.ErrNotFound
	}

	d.incomingShares[share.ShareId] = share
	d.providerIndex[providerKey(share.SendingServer, share.ProviderId)] = share.ShareId

	return d.saveFile("incoming_shares.json", d.incomingShares)
}

// DeleteIncomingShare deletes an incoming share.
func (d *Driver) DeleteIncomingShare(ctx context.Context, shareId string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return store.ErrClosed
	}

	share, exists := d.incomingShares[shareId]
	if !exists {
		return store.ErrNotFound
	}

	delete(d.providerIndex, providerKey(share.SendingServer, share.ProviderId))
	delete(d.incomingShares, shareId)

	return d.saveFile("incoming_shares.json", d.incomingShares)
}

// ListIncomingShares returns incoming shares for a user.
func (d *Driver) ListIncomingShares(ctx context.Context, userId string) ([]*store.IncomingShare, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.closed {
		return nil, store.ErrClosed
	}

	shares := make([]*store.IncomingShare, 0)
	for _, share := range d.incomingShares {
		if userId == "" || share.UserId == userId {
			shares = append(shares, share)
		}
	}
	return shares, nil
}

// Compile-time interface checks
var _ store.Driver = (*Driver)(nil)
var _ store.ShareStore = (*Driver)(nil)
