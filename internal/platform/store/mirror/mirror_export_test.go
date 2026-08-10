// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package mirror

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

//nolint:paralleltest // mutates package-level dirSync seam for deterministic call counting
func TestMirrorStore_DirectoryFsyncAfterRename(t *testing.T) {
	orig := dirSync

	t.Cleanup(func() { dirSync = orig })

	dir := t.TempDir()
	mirrorDir := filepath.Join(dir, "mirror")

	if err := os.MkdirAll(mirrorDir, 0700); err != nil {
		t.Fatal(err)
	}

	d := &Driver{dataDir: dir}

	calls := 0
	syncedDir := ""
	dirSync = func(name string) error {
		calls++
		syncedDir = name

		return nil
	}

	if err := d.writeJSON("outgoing_shares.json", []any{}); err != nil {
		t.Fatalf("writeJSON: %v", err)
	}

	if calls != 1 {
		t.Fatalf("dirSync calls = %d, want 1", calls)
	}

	wantDir := filepath.Clean(mirrorDir)
	if syncedDir != wantDir {
		t.Errorf("dirSync dir = %q, want %q", syncedDir, wantDir)
	}

	dirSync = func(_ string) error {
		return syscall.EINVAL
	}

	if err := d.writeJSON("incoming_shares.json", []any{}); err != nil {
		t.Fatalf("writeJSON with EINVAL dirSync: %v", err)
	}
}
