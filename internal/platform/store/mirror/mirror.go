// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// Package mirror implements a SQLite + JSON mirror persistence driver.
// SQLite is the source of truth; JSON is a one-way export for supervisor visibility.
// The program MUST NOT read JSON as input.
//
// Internal layout: driver struct and lifecycle followed by four CRUD surfaces
// (OutgoingShare, IncomingShare, OutgoingInvite, IncomingInvite) - all delegated
// to sqlitecore - then the JSON projection/export subsystem at the bottom of
// the file.
package mirror

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/sqlitecore"
)

func init() {
	store.Register("mirror", NewDriver)
}

// Driver implements the store.Driver interface with SQLite + JSON mirror.
// SQLite is the source of truth; JSON is a one-way export for supervisor visibility.
// It implements all four persistence surfaces: OutgoingShareStore,
// IncomingShareStore, OutgoingInviteStore, and IncomingInviteStore.
type Driver struct {
	dataDir string
	core    *sqlitecore.Core
	mu      sync.Mutex // protects JSON export operations
}

// NewDriver creates a new mirror driver instance.
func NewDriver(cfg *store.DriverConfig) (store.Driver, error) {
	if cfg.DataDir == "" {
		return nil, fmt.Errorf("data_dir is required for mirror driver")
	}

	return &Driver{
		dataDir: cfg.DataDir,
	}, nil
}

// Name returns the driver name.
func (d *Driver) Name() string {
	return "mirror"
}

// Init creates the mirror directory, opens the shared SQLite core, and exports
// the initial state to JSON.
func (d *Driver) Init(ctx context.Context) error {
	mirrorDir := filepath.Join(d.dataDir, "mirror")
	if err := os.MkdirAll(mirrorDir, 0700); err != nil {
		return fmt.Errorf("failed to create mirror dir: %w", err)
	}

	core, err := sqlitecore.Open(d.dataDir)
	if err != nil {
		return fmt.Errorf("store: open database: %w", err)
	}

	d.core = core

	if exportErr := d.exportAll(ctx); exportErr != nil {
		exportErr = fmt.Errorf("failed to export mirror: %w", exportErr)
		closeErr := d.core.Close()
		d.core = nil

		if closeErr != nil {
			return errors.Join(exportErr, closeErr)
		}

		return exportErr
	}

	return nil
}

// Close closes the database connection.
func (d *Driver) Close() error {
	if err := d.core.Close(); err != nil {
		return fmt.Errorf("store: close database: %w", err)
	}

	return nil
}

// ----------------------------------------------------------------------------
// CRUD surfaces - delegates to sqlitecore and triggers a JSON export after
// successful writes.
// ----------------------------------------------------------------------------

// OutgoingShareStore implementation

// CreateOutgoingShare creates a new outgoing share.
func (d *Driver) CreateOutgoingShare(ctx context.Context, share *store.OutgoingShare) error {
	if err := d.core.CreateOutgoingShare(ctx, share); err != nil {
		return fmt.Errorf("store: create outgoing share: %w", err)
	}

	d.logExportError(ctx, "CreateOutgoingShare", d.lockedExport(ctx, d.exportOutgoingShares))

	return nil
}

// GetOutgoingShareByID retrieves an outgoing share by its local share id.
func (d *Driver) GetOutgoingShareByID(ctx context.Context, shareID string) (*store.OutgoingShare, error) {
	share, err := d.core.GetOutgoingShareByID(ctx, shareID)
	if err != nil {
		return nil, fmt.Errorf("store: get outgoing share by id: %w", err)
	}

	return share, nil
}

// GetOutgoingShare retrieves an outgoing share by providerID.
func (d *Driver) GetOutgoingShare(ctx context.Context, providerID string) (*store.OutgoingShare, error) {
	share, err := d.core.GetOutgoingShare(ctx, providerID)
	if err != nil {
		return nil, fmt.Errorf("store: get outgoing share: %w", err)
	}

	return share, nil
}

// GetOutgoingShareByWebDAVID retrieves an outgoing share by webdavID.
func (d *Driver) GetOutgoingShareByWebDAVID(ctx context.Context, webdavID string) (*store.OutgoingShare, error) {
	share, err := d.core.GetOutgoingShareByWebDAVID(ctx, webdavID)
	if err != nil {
		return nil, fmt.Errorf("store: get outgoing share by webdav id: %w", err)
	}

	return share, nil
}

// GetOutgoingShareBySharedSecret retrieves an outgoing share by shared secret.
func (d *Driver) GetOutgoingShareBySharedSecret(ctx context.Context, sharedSecret string) (*store.OutgoingShare, error) {
	share, err := d.core.GetOutgoingShareBySharedSecret(ctx, sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("store: get outgoing share by shared secret: %w", err)
	}

	return share, nil
}

// UpdateOutgoingShare updates an existing outgoing share.
func (d *Driver) UpdateOutgoingShare(ctx context.Context, share *store.OutgoingShare) error {
	if err := d.core.UpdateOutgoingShare(ctx, share); err != nil {
		return fmt.Errorf("store: update outgoing share: %w", err)
	}

	d.logExportError(ctx, "UpdateOutgoingShare", d.lockedExport(ctx, d.exportOutgoingShares))

	return nil
}

// DeleteOutgoingShare deletes an outgoing share.
func (d *Driver) DeleteOutgoingShare(ctx context.Context, providerID string) error {
	if err := d.core.DeleteOutgoingShare(ctx, providerID); err != nil {
		return fmt.Errorf("store: delete outgoing share: %w", err)
	}

	d.logExportError(ctx, "DeleteOutgoingShare", d.lockedExport(ctx, d.exportOutgoingShares))

	return nil
}

// ListOutgoingShares returns all outgoing shares.
func (d *Driver) ListOutgoingShares(ctx context.Context) ([]*store.OutgoingShare, error) {
	shares, err := d.core.ListOutgoingShares(ctx)
	if err != nil {
		return nil, fmt.Errorf("store: list outgoing shares: %w", err)
	}

	return shares, nil
}

// IncomingShareStore implementation

// CreateIncomingShare creates a new incoming share.
func (d *Driver) CreateIncomingShare(ctx context.Context, share *store.IncomingShare) error {
	if err := d.core.CreateIncomingShare(ctx, share); err != nil {
		return fmt.Errorf("store: create incoming share: %w", err)
	}

	d.logExportError(ctx, "CreateIncomingShare", d.lockedExport(ctx, d.exportIncomingShares))

	return nil
}

// GetIncomingShareByIDForRecipient retrieves an incoming share by shareID scoped to a recipient.
func (d *Driver) GetIncomingShareByIDForRecipient(ctx context.Context, shareID string, recipientUserID string) (*store.IncomingShare, error) {
	share, err := d.core.GetIncomingShareByIDForRecipient(ctx, shareID, recipientUserID)
	if err != nil {
		return nil, fmt.Errorf("store: get incoming share by id for recipient: %w", err)
	}

	return share, nil
}

// GetIncomingShareByProviderKey retrieves an incoming share by sending server and providerID.
func (d *Driver) GetIncomingShareByProviderKey(ctx context.Context, sendingServer, providerID string) (*store.IncomingShare, error) {
	share, err := d.core.GetIncomingShareByProviderKey(ctx, sendingServer, providerID)
	if err != nil {
		return nil, fmt.Errorf("store: get incoming share by provider key: %w", err)
	}

	return share, nil
}

// ListIncomingSharesByRecipient returns incoming shares for the given recipient user.
func (d *Driver) ListIncomingSharesByRecipient(ctx context.Context, recipientUserID string) ([]*store.IncomingShare, error) {
	shares, err := d.core.ListIncomingSharesByRecipient(ctx, recipientUserID)
	if err != nil {
		return nil, fmt.Errorf("store: list incoming shares by recipient: %w", err)
	}

	return shares, nil
}

// UpdateIncomingShareStatusForRecipient updates the status of an incoming share, scoped to a recipient.
func (d *Driver) UpdateIncomingShareStatusForRecipient(ctx context.Context, shareID string, recipientUserID string, status string) error {
	if err := d.core.UpdateIncomingShareStatusForRecipient(ctx, shareID, recipientUserID, status); err != nil {
		return fmt.Errorf("store: update incoming share status for recipient: %w", err)
	}

	d.logExportError(ctx, "UpdateIncomingShareStatusForRecipient", d.lockedExport(ctx, d.exportIncomingShares))

	return nil
}

// DeleteIncomingShareForRecipient deletes an incoming share, scoped to a recipient.
func (d *Driver) DeleteIncomingShareForRecipient(ctx context.Context, shareID string, recipientUserID string) error {
	if err := d.core.DeleteIncomingShareForRecipient(ctx, shareID, recipientUserID); err != nil {
		return fmt.Errorf("store: delete incoming share for recipient: %w", err)
	}

	d.logExportError(ctx, "DeleteIncomingShareForRecipient", d.lockedExport(ctx, d.exportIncomingShares))

	return nil
}

// OutgoingInviteStore implementation

// CreateOutgoingInvite creates a new outgoing invite.
func (d *Driver) CreateOutgoingInvite(ctx context.Context, invite *store.OutgoingInvite) error {
	if err := d.core.CreateOutgoingInvite(ctx, invite); err != nil {
		return fmt.Errorf("store: create outgoing invite: %w", err)
	}

	d.logExportError(ctx, "CreateOutgoingInvite", d.lockedExport(ctx, d.exportOutgoingInvites))

	return nil
}

// GetOutgoingInvite retrieves an outgoing invite by id.
func (d *Driver) GetOutgoingInvite(ctx context.Context, id string) (*store.OutgoingInvite, error) {
	invite, err := d.core.GetOutgoingInvite(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("store: get outgoing invite: %w", err)
	}

	return invite, nil
}

// GetOutgoingInviteByToken retrieves an outgoing invite by token.
func (d *Driver) GetOutgoingInviteByToken(ctx context.Context, token string) (*store.OutgoingInvite, error) {
	invite, err := d.core.GetOutgoingInviteByToken(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("store: get outgoing invite by token: %w", err)
	}

	return invite, nil
}

// UpdateOutgoingInvite updates an existing outgoing invite.
func (d *Driver) UpdateOutgoingInvite(ctx context.Context, invite *store.OutgoingInvite) error {
	if err := d.core.UpdateOutgoingInvite(ctx, invite); err != nil {
		return fmt.Errorf("store: update outgoing invite: %w", err)
	}

	d.logExportError(ctx, "UpdateOutgoingInvite", d.lockedExport(ctx, d.exportOutgoingInvites))

	return nil
}

// DeleteOutgoingInvite deletes an outgoing invite by id.
func (d *Driver) DeleteOutgoingInvite(ctx context.Context, id string) error {
	if err := d.core.DeleteOutgoingInvite(ctx, id); err != nil {
		return fmt.Errorf("store: delete outgoing invite: %w", err)
	}

	d.logExportError(ctx, "DeleteOutgoingInvite", d.lockedExport(ctx, d.exportOutgoingInvites))

	return nil
}

// ListOutgoingInvites returns outgoing invites for a user.
func (d *Driver) ListOutgoingInvites(ctx context.Context, userID string) ([]*store.OutgoingInvite, error) {
	invites, err := d.core.ListOutgoingInvites(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("store: list outgoing invites: %w", err)
	}

	return invites, nil
}

// IncomingInviteStore implementation

// CreateIncomingInvite creates a new incoming invite.
func (d *Driver) CreateIncomingInvite(ctx context.Context, invite *store.IncomingInvite) error {
	if err := d.core.CreateIncomingInvite(ctx, invite); err != nil {
		return fmt.Errorf("store: create incoming invite: %w", err)
	}

	d.logExportError(ctx, "CreateIncomingInvite", d.lockedExport(ctx, d.exportIncomingInvites))

	return nil
}

// GetIncomingInviteForRecipient retrieves an incoming invite by id scoped to a recipient.
func (d *Driver) GetIncomingInviteForRecipient(ctx context.Context, id string, recipientUserID string) (*store.IncomingInvite, error) {
	invite, err := d.core.GetIncomingInviteForRecipient(ctx, id, recipientUserID)
	if err != nil {
		return nil, fmt.Errorf("store: get incoming invite for recipient: %w", err)
	}

	return invite, nil
}

// GetIncomingInviteByToken retrieves an incoming invite by token scoped to a recipient.
func (d *Driver) GetIncomingInviteByToken(ctx context.Context, token string, recipientUserID string) (*store.IncomingInvite, error) {
	invite, err := d.core.GetIncomingInviteByToken(ctx, token, recipientUserID)
	if err != nil {
		return nil, fmt.Errorf("store: get incoming invite by token: %w", err)
	}

	return invite, nil
}

// UpdateIncomingInviteStatusForRecipient updates the status of an incoming
// invite scoped to a recipient, persisting the remote sender identity on
// acceptance when provided.
func (d *Driver) UpdateIncomingInviteStatusForRecipient(ctx context.Context, id string, recipientUserID string, status string, senderUserID string, senderFQDNNormalized string) error {
	if err := d.core.UpdateIncomingInviteStatusForRecipient(ctx, id, recipientUserID, status, senderUserID, senderFQDNNormalized); err != nil {
		return fmt.Errorf("store: update incoming invite status for recipient: %w", err)
	}

	d.logExportError(ctx, "UpdateIncomingInviteStatusForRecipient", d.lockedExport(ctx, d.exportIncomingInvites))

	return nil
}

// DeleteIncomingInviteForRecipient deletes an incoming invite scoped to a recipient.
func (d *Driver) DeleteIncomingInviteForRecipient(ctx context.Context, id string, recipientUserID string) error {
	if err := d.core.DeleteIncomingInviteForRecipient(ctx, id, recipientUserID); err != nil {
		return fmt.Errorf("store: delete incoming invite for recipient: %w", err)
	}

	d.logExportError(ctx, "DeleteIncomingInviteForRecipient", d.lockedExport(ctx, d.exportIncomingInvites))

	return nil
}

// ListIncomingInvites returns incoming invites for a recipient user.
func (d *Driver) ListIncomingInvites(ctx context.Context, recipientUserID string) ([]*store.IncomingInvite, error) {
	invites, err := d.core.ListIncomingInvites(ctx, recipientUserID)
	if err != nil {
		return nil, fmt.Errorf("store: list incoming invites: %w", err)
	}

	return invites, nil
}

// Compile-time interface checks
var _ store.Driver = (*Driver)(nil)
var _ store.OutgoingShareStore = (*Driver)(nil)
var _ store.IncomingShareStore = (*Driver)(nil)
var _ store.OutgoingInviteStore = (*Driver)(nil)
var _ store.IncomingInviteStore = (*Driver)(nil)

// ----------------------------------------------------------------------------
// JSON projection/export subsystem
//
// Invariants:
//   - Nothing below reads JSON back in.
//   - Export failures are logged but never propagated after a successful SQLite write.
//   - Redaction is applied to in-memory copies only; stored rows are unchanged.
// ----------------------------------------------------------------------------

// exportAll exports all four persistence surfaces to JSON files.
// It holds mu for the duration so concurrent writes do not interleave exports.
func (d *Driver) exportAll(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if err := d.exportOutgoingShares(ctx); err != nil {
		return err
	}

	if err := d.exportIncomingShares(ctx); err != nil {
		return err
	}

	if err := d.exportOutgoingInvites(ctx); err != nil {
		return err
	}

	if err := d.exportIncomingInvites(ctx); err != nil {
		return err
	}

	return nil
}

// lockedExport serializes a single-surface JSON export under mu, preventing
// concurrent writes from racing on the shared *.tmp path used by writeJSON.
func (d *Driver) lockedExport(ctx context.Context, fn func(context.Context) error) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	return fn(ctx)
}

// exportOutgoingShares projects outgoing shares to JSON with shared secrets redacted.
func (d *Driver) exportOutgoingShares(ctx context.Context) error {
	shares, err := d.core.ListOutgoingShares(ctx)
	if err != nil {
		return fmt.Errorf("store: list outgoing shares: %w", err)
	}

	for _, share := range shares {
		share.SharedSecret = ""
	}

	return d.writeJSON("outgoing_shares.json", shares)
}

// exportIncomingShares projects all incoming shares to JSON with shared secrets redacted.
func (d *Driver) exportIncomingShares(ctx context.Context) error {
	shares, err := d.core.ListAllIncomingShares(ctx)
	if err != nil {
		return fmt.Errorf("store: list all incoming shares: %w", err)
	}

	for _, share := range shares {
		share.SharedSecret = ""
	}

	return d.writeJSON("incoming_shares.json", shares)
}

// exportOutgoingInvites projects all outgoing invites to JSON with tokens redacted.
func (d *Driver) exportOutgoingInvites(ctx context.Context) error {
	// Empty userID means all invites; see sqlitecore.ListOutgoingInvites.
	invites, err := d.core.ListOutgoingInvites(ctx, "")
	if err != nil {
		return fmt.Errorf("store: list outgoing invites: %w", err)
	}

	for _, invite := range invites {
		invite.Token = ""
	}

	return d.writeJSON("outgoing_invites.json", invites)
}

// exportIncomingInvites projects all incoming invites to JSON with tokens redacted.
func (d *Driver) exportIncomingInvites(ctx context.Context) error {
	invites, err := d.core.ListAllIncomingInvites(ctx)
	if err != nil {
		return fmt.Errorf("store: list all incoming invites: %w", err)
	}

	for _, invite := range invites {
		invite.Token = ""
	}

	return d.writeJSON("incoming_invites.json", invites)
}

// writeJSON atomically writes data to a JSON file in the mirror directory.
// It writes to a temp file, syncs, then renames to avoid partial reads.
func (d *Driver) writeJSON(filename string, data any) error {
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
		cleanupMirrorTempSave(f, tempPath)

		return fmt.Errorf("failed to write temp file: %w", err)
	}

	if err := f.Sync(); err != nil {
		cleanupMirrorTempSave(f, tempPath)

		return fmt.Errorf("failed to sync temp file: %w", err)
	}

	if err := f.Close(); err != nil {
		//nolint:errcheck // best-effort cleanup; error is not actionable
		os.Remove(tempPath)
		return fmt.Errorf("failed to close temp file: %w", err)
	}

	if err := os.Rename(tempPath, path); err != nil {
		//nolint:errcheck // best-effort cleanup; error is not actionable
		os.Remove(tempPath)
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	return nil
}

func cleanupMirrorTempSave(f *os.File, tempPath string) {
	//nolint:errcheck // best-effort cleanup; error is not actionable
	f.Close()
	//nolint:errcheck // best-effort cleanup; error is not actionable
	os.Remove(tempPath)
}

// logExportError logs a JSON export failure without returning it to the caller.
// SQLite is the source of truth; a failed JSON export does not mean the write
// failed - the caller's data is safe in SQLite. The mirror may be temporarily
// stale until the next successful write triggers a fresh export.
func (d *Driver) logExportError(ctx context.Context, op string, err error) {
	if err != nil {
		slog.WarnContext(
			ctx,
			"JSON mirror export failed after SQLite commit; mirror may be stale until next write",
			"op", op,
			"err", err,
		)
	}
}
