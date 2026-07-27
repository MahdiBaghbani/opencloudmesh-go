package json

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// JSON file names for each data surface.
const (
	fileOutgoingShares  = "outgoing_shares.json"
	fileIncomingShares  = "incoming_shares.json"
	fileOutgoingInvites = "outgoing_invites.json"
	fileIncomingInvites = "incoming_invites.json"
)

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

	f, err := os.OpenFile(tempPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}

	if _, err := f.Write(jsonData); err != nil {
		cleanupTempSave(f, tempPath)

		return fmt.Errorf("failed to write temp file: %w", err)
	}

	if err := f.Sync(); err != nil {
		cleanupTempSave(f, tempPath)

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

func cleanupTempSave(f *os.File, tempPath string) {
	//nolint:errcheck // best-effort cleanup; error is not actionable
	f.Close()
	//nolint:errcheck // best-effort cleanup; error is not actionable
	os.Remove(tempPath)
}
