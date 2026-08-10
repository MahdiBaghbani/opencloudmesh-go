// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package json

import (
	"path/filepath"
	"syscall"
	"testing"
)

//nolint:paralleltest // mutates package-level dirSync seam for deterministic call counting
func TestJSONStore_DirectoryFsyncAfterRename(t *testing.T) {
	orig := dirSync

	t.Cleanup(func() { dirSync = orig })

	dir := t.TempDir()
	d := &Driver{dataDir: dir}

	calls := 0
	syncedDir := ""
	dirSync = func(name string) error {
		calls++
		syncedDir = name

		return nil
	}

	if err := d.saveFile(fileOutgoingShares, map[string]any{}); err != nil {
		t.Fatalf("saveFile: %v", err)
	}

	if calls != 1 {
		t.Fatalf("dirSync calls = %d, want 1", calls)
	}

	wantDir := filepath.Clean(dir)
	if syncedDir != wantDir {
		t.Errorf("dirSync dir = %q, want %q", syncedDir, wantDir)
	}

	dirSync = func(_ string) error {
		return syscall.EINVAL
	}

	if err := d.saveFile(fileIncomingShares, map[string]any{}); err != nil {
		t.Fatalf("saveFile with EINVAL dirSync: %v", err)
	}
}
