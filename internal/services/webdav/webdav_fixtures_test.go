// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package webdav

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token"
	tsrepos "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/repos"
)

func testWebDAVInputs(t *testing.T) Inputs {
	t.Helper()

	return Inputs{
		OutgoingShareRepo: tsrepos.OpenMemory(t).OutgoingShares,
		TokenStore:        token.NewMemoryTokenStore(),
	}
}
