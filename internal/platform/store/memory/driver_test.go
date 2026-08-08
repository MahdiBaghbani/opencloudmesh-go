// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package memory_test

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/memory"
	testutil "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/store"
)

func TestMemoryDriver(t *testing.T) {
	t.Parallel()
	tempDir := testutil.TempDataDir(t, "ocm-test-memory-*")

	cfg := &store.DriverConfig{
		Driver:  "memory",
		DataDir: tempDir,
	}

	testutil.RunDriverTests(t, "memory", cfg)
}
