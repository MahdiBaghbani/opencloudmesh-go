// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package wellknown

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery/resolve"
)

func TestProviderConfig_ApplyDefaults(t *testing.T) {
	t.Parallel()

	c := &resolve.ProviderConfig{}
	c.ApplyDefaults()

	if c.Provider != "OpenCloudMesh" {
		t.Errorf("expected Provider 'OpenCloudMesh', got %q", c.Provider)
	}
}

func TestProviderConfig_ApplyDefaults_PreservesCustomValues(t *testing.T) {
	t.Parallel()

	c := &resolve.ProviderConfig{
		Provider: "CustomProvider",
	}
	c.ApplyDefaults()

	if c.Provider != "CustomProvider" {
		t.Errorf("expected Provider 'CustomProvider', got %q", c.Provider)
	}
}
