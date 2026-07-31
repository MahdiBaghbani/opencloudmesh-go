// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// Package localidentity provides shared test fixtures for local public identity.
package localidentity

import (
	"testing"

	li "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/localidentity"
)

// MustTestIdentity derives Identity from publicOrigin and externalBasePath or fatals the test.
func MustTestIdentity(t *testing.T, publicOrigin, externalBasePath string) li.Identity {
	t.Helper()

	id, err := li.Derive(publicOrigin, externalBasePath)
	if err != nil {
		t.Fatalf("localidentity.Derive(%q, %q): %v", publicOrigin, externalBasePath, err)
	}

	return id
}
