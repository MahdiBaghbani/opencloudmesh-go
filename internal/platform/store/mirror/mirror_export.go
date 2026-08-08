// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package mirror

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
)

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
