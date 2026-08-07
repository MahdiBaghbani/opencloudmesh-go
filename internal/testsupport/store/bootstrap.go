// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package store

import (
	"context"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
)

// TempDataDir creates an isolated temporary data directory for a store driver
// test via t.TempDir(). The pattern argument is ignored and kept for call-site
// compatibility; cleanup is managed by testing.T.
func TempDataDir(t *testing.T, _ string) string {
	t.Helper()

	return t.TempDir()
}

// OpenDriver constructs a store driver from cfg and initializes it, failing the
// test on any error. The caller owns the returned driver and is responsible for
// closing it. OpenDriver intentionally does not register a close with t.Cleanup
// so that close/reopen durability tests can manage the driver lifecycle
// explicitly (open, close, reopen from the same cfg).
func OpenDriver(t *testing.T, cfg *store.DriverConfig) store.Driver {
	t.Helper()

	d, err := store.New(cfg)
	if err != nil {
		t.Fatalf("create %s driver: %v", cfg.Driver, err)
	}

	if err := d.Init(context.Background()); err != nil {
		if closeErr := d.Close(); closeErr != nil {
			t.Fatalf("init %s driver: %v (close after init failure: %v)", cfg.Driver, err, closeErr)
		}

		t.Fatalf("init %s driver: %v", cfg.Driver, err)
	}

	return d
}
