// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package routing

import (
	"slices"
	"testing"
)

func TestHostRootDiscoveryPaths_CanonicalOnly(t *testing.T) {
	paths := HostRootDiscoveryPaths()

	want := []string{"/.well-known/ocm"}
	if !slices.Equal(paths, want) {
		t.Fatalf("HostRootDiscoveryPaths() = %v, want %v", paths, want)
	}
}
