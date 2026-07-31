// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package integration

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/localidentity"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
	tsrouting "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/routing"
	"github.com/MahdiBaghbani/opencloudmesh-go/tests/integration/harness"
)

func TestDiscoveryRoutesMatchRouteInventory(t *testing.T) {
	for _, variant := range tsrouting.MatrixVariants() {
		t.Run(variant.Name, func(t *testing.T) {
			ts := harness.StartTestServerWithConfig(t, matrixConfigPatch(variant))
			disc := getLiveDiscovery(t, ts.BaseURL)
			assertDiscoveryMatchesProjection(t, ts, disc)
		})
	}
}

// getLiveDiscovery fetches and decodes the well-known discovery document.
func getLiveDiscovery(t *testing.T, baseURL string) spec.Discovery {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, baseURL+"/.well-known/ocm", nil)
	if err != nil {
		t.Fatalf("build discovery request: %v", err)
	}

	resp, err := http.DefaultClient.Do(req) //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	if err != nil {
		t.Fatalf("discovery GET failed: %v", err)
	}
	defer tshttp.MustClose(t, resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("discovery status = %d", resp.StatusCode)
	}

	var disc spec.Discovery
	if err := json.NewDecoder(resp.Body).Decode(&disc); err != nil {
		t.Fatalf("decode discovery: %v", err)
	}

	return disc
}

// assertDiscoveryMatchesProjection compares the served discovery document
// with the paths projected from the route inventory.
func assertDiscoveryMatchesProjection(t *testing.T, ts *harness.TestServer, disc spec.Discovery) {
	t.Helper()

	opts := service.RouteOptsFromConfig(ts.Config)

	identity, err := localidentity.Derive(ts.Config.PublicOrigin, ts.Config.ExternalBasePath)
	if err != nil {
		t.Fatalf("Derive identity: %v", err)
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

	if disc.HasCapability("http-sig") && disc.JwksUri != projected.JwksURI {
		t.Errorf("JwksUri = %q, want %q", disc.JwksUri, projected.JwksURI)
	}

	path, ok := disc.ResourceTypes[0].Protocols.StringRole("webdav")
	if !ok || path != projected.WebDAVRoot {
		t.Errorf("webdav = %q, want %q, ok=%v", path, projected.WebDAVRoot, ok)
	}

	if projected.InviteAcceptDialog != "" && disc.InviteAcceptDialog != projected.InviteAcceptDialog {
		t.Errorf("InviteAcceptDialog = %q, want %q", disc.InviteAcceptDialog, projected.InviteAcceptDialog)
	}
}
