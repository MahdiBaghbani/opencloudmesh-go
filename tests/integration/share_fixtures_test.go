// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package integration

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

func writeShareFileInContentRoot(t *testing.T, serverTempDir, fileName string, content []byte) string {
	t.Helper()

	rootDir := filepath.Join(serverTempDir, config.DefaultContentDir)
	if err := os.MkdirAll(rootDir, 0700); err != nil {
		t.Fatalf("create content root %q: %v", rootDir, err)
	}

	path := filepath.Join(rootDir, fileName)
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatalf("write share file %q in content root: %v", path, err)
	}

	return path
}
