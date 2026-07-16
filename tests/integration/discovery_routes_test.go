// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package integration

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/localidentity"
	tsrouting "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/routing"
	"github.com/MahdiBaghbani/opencloudmesh-go/tests/integration/harness"
)

func TestDiscoveryRoutesMatchRouteInventory(t *testing.T) {
	for _, variant := range tsrouting.MatrixVariants() {
		t.Run(variant.Name, func(t *testing.T) {
			ts := harness.StartTestServerWithConfig(t, matrixConfigPatch(variant))
			opts := service.RouteOptsFromConfig(ts.Config)

			identity, err := localidentity.Derive(ts.Config.PublicOrigin, ts.Config.ExternalBasePath)
			if err != nil {
				t.Fatalf("Derive identity: %v", err)
			}

			resp, err := http.Get(ts.BaseURL + "/.well-known/ocm")
			if err != nil {
				t.Fatalf("discovery GET failed: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("discovery status = %d", resp.StatusCode)
			}

			var disc spec.Discovery
			if err := json.NewDecoder(resp.Body).Decode(&disc); err != nil {
				t.Fatalf("decode discovery: %v", err)
			}

			projected, ok := spec.DeriveDiscoveryPaths(identity, opts)
			if !ok {
				t.Fatal("expected route projection ok")
			}

			if disc.EndPoint != projected.EndPoint {
				t.Errorf("EndPoint = %q, want %q", disc.EndPoint, projected.EndPoint)
			}
			if disc.HasCapability("exchange-token") && disc.TokenEndPoint != projected.TokenEndPoint {
				t.Errorf("TokenEndPoint = %q, want %q", disc.TokenEndPoint, projected.TokenEndPoint)
			}
			path, ok := disc.ResourceTypes[0].Protocols.StringRole("webdav")
			if !ok || path != projected.WebDAVRoot {
				t.Errorf("webdav = %q, want %q, ok=%v", path, projected.WebDAVRoot, ok)
			}
			if projected.InviteAcceptDialog != "" && disc.InviteAcceptDialog != projected.InviteAcceptDialog {
				t.Errorf("InviteAcceptDialog = %q, want %q", disc.InviteAcceptDialog, projected.InviteAcceptDialog)
			}
		})
	}
}
