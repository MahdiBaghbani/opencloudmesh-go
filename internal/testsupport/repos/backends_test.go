// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package repos

import (
	"slices"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

func TestBackendListsDerivedFromAllBackends(t *testing.T) {
	t.Parallel()

	all := AllBackends()

	openNames := make([]string, len(OpenTestRepos()))
	for i, tr := range OpenTestRepos() {
		openNames[i] = tr.Name
	}

	if !slices.Equal(openNames, all) {
		t.Fatalf("OpenTestRepos names = %v, want AllBackends = %v", openNames, all)
	}

	wantDurable := []string{
		config.BackendJSON,
		config.BackendSQLite,
		config.BackendMirror,
	}
	if !slices.Equal(DurableBackends(), wantDurable) {
		t.Fatalf("DurableBackends() = %v, want %v", DurableBackends(), wantDurable)
	}
}
