// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package store_test

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/json"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/mirror"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/sqlite"
)

func TestDriverRegistry(t *testing.T) {
	drivers := store.AvailableDrivers()

	expected := map[string]bool{"json": true, "sqlite": true, "mirror": true}
	for _, d := range drivers {
		if !expected[d] {
			t.Logf("unexpected driver registered: %s", d)
		}

		delete(expected, d)
	}

	for d := range expected {
		t.Errorf("expected driver %q not registered", d)
	}
}
