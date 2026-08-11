// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package discovery_test

import (
	"encoding/json"
	"net/url"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
)

// sortedProtocolKeys returns the protocol map keys in sorted order.
func sortedProtocolKeys(protocols spec.Protocols) []string {
	keys := make([]string, 0, len(protocols))
	for key := range protocols {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	return keys
}

func TestBuildDiscovery_DisabledWhenNoEndPoint(t *testing.T) {
	t.Parallel()

	disc := discovery.BuildDiscovery(discovery.BuildParams{Provider: "OpenCloudMesh"}, nil)
	if disc.Enabled {
		t.Error("expected Enabled=false when endPoint is empty")
	}
}

func TestBuildDiscovery_DisabledWhenInvalidEndPoint(t *testing.T) {
	t.Parallel()

	disc := discovery.BuildDiscovery(discovery.BuildParams{EndPoint: "://invalid-url"}, nil)
	if disc.Enabled {
		t.Error("expected Enabled=false for invalid URL")
	}
}

func TestBuildDiscovery_EnabledWithProjectedPaths(t *testing.T) {
	t.Parallel()

	disc := discovery.BuildDiscovery(discovery.BuildParams{
		EndPoint:   "https://example.com/myapp/ocm",
		WebDAVRoot: "/webdav/ocm/",
	}, nil)

	if !disc.Enabled {
		t.Fatal("expected Enabled=true")
	}

	if disc.EndPoint != "https://example.com/myapp/ocm" {
		t.Errorf("EndPoint = %q", disc.EndPoint)
	}

	path, ok := disc.ResourceTypes[0].Protocols.StringRole("webdav")
	if !ok || path != "/webdav/ocm/" {
		t.Errorf("webdav protocol = %q, ok=%v", path, ok)
	}
}

func TestBuildDiscovery_TokenExchangeUsesProjectedEndpoint(t *testing.T) {
	t.Parallel()

	disc := discovery.BuildDiscovery(discovery.BuildParams{
		EndPoint:             "https://example.com/app/ocm",
		TokenEndPoint:        "https://example.com/app/ocm/exchange",
		TokenExchangeCapable: true,
	}, nil)

	if !disc.HasCapability("exchange-token") {
		t.Error("expected exchange-token capability")
	}

	if disc.TokenEndPoint != "https://example.com/app/ocm/exchange" {
		t.Errorf("TokenEndPoint = %q", disc.TokenEndPoint)
	}
}

func TestBuildDiscovery_CriteriaUseIETFStrings(t *testing.T) {
	t.Parallel()

	disc := discovery.BuildDiscovery(discovery.BuildParams{
		EndPoint:               "https://example.com/ocm",
		WebDAVRoot:             "/webdav/ocm/",
		TokenEndPoint:          "https://example.com/ocm/token",
		AdvertiseHTTPSig:       true,
		TokenExchangeCapable:   true,
		RequiresTokenExchange:  true,
		RequiresHTTPSignatures: true,
	}, nil)

	if !disc.HasCriteria(spec.CriteriaMustUseHTTPSig) {
		t.Error("expected must-use-http-sig criterion")
	}

	if !disc.HasCriteria(spec.CriteriaMustExchangeToken) {
		t.Error("expected must-exchange-token criterion")
	}
}

func TestBuildDiscovery_OmitsTokenExchangeWhenEndpointEmpty(t *testing.T) {
	t.Parallel()

	disc := discovery.BuildDiscovery(discovery.BuildParams{
		EndPoint:              "https://example.com/ocm",
		WebDAVRoot:            "/webdav/ocm/",
		TokenExchangeCapable:  true,
		RequiresTokenExchange: true,
	}, nil)

	if disc.HasCapability("exchange-token") {
		t.Error("did not expect exchange-token without token endpoint")
	}

	if disc.TokenEndPoint != "" {
		t.Errorf("TokenEndPoint = %q, want empty", disc.TokenEndPoint)
	}

	if disc.HasCriteria(spec.CriteriaMustExchangeToken) {
		t.Error("did not expect must-exchange-token without token endpoint")
	}
}

func TestBuildDiscovery_InviteAcceptIndependentFromWAYF(t *testing.T) {
	t.Parallel()

	disc := discovery.BuildDiscovery(discovery.BuildParams{
		EndPoint:           "https://example.com/ocm",
		WebDAVRoot:         "/webdav/ocm/",
		InviteAcceptDialog: "https://example.com/ui/accept-invite",
		WayfEnabled:        false,
	}, nil)

	if disc.InviteAcceptDialog == "" {
		t.Error("expected inviteAcceptDialog without invite-wayf")
	}

	if disc.HasCapability("invite-wayf") {
		t.Error("did not expect invite-wayf capability")
	}
}

func TestBuildDiscovery_InvitesCapabilityFromRouteFlag(t *testing.T) {
	t.Parallel()

	disc := discovery.BuildDiscovery(discovery.BuildParams{
		EndPoint:       "https://example.com/ocm",
		WebDAVRoot:     "/webdav/ocm/",
		InvitesEnabled: true,
	}, nil)

	if !disc.HasCapability("invites") {
		t.Error("expected invites capability when invites route is enabled")
	}
}

func TestBuildDiscovery_InviteWAYFFromRouteFlag(t *testing.T) {
	t.Parallel()

	disc := discovery.BuildDiscovery(discovery.BuildParams{
		EndPoint:    "https://example.com/ocm",
		WebDAVRoot:  "/webdav/ocm/",
		WayfEnabled: true,
	}, nil)

	if !disc.HasCapability("invite-wayf") {
		t.Error("expected invite-wayf when WAYF route is enabled")
	}
}

func TestBuildDiscovery_AdvertiseHTTPSigWithoutInlinePublicKeys(t *testing.T) {
	t.Parallel()

	disc := discovery.BuildDiscovery(discovery.BuildParams{
		EndPoint:         "https://example.com/ocm",
		WebDAVRoot:       "/webdav/ocm/",
		AdvertiseHTTPSig: true,
	}, nil)

	if !disc.IsHTTPSigCapable() {
		t.Error("expected http-sig capability from AdvertiseHTTPSig")
	}

	out, err := json.Marshal(disc)
	if err != nil {
		t.Fatalf("marshal discovery: %v", err)
	}

	if strings.Contains(string(out), "publicKey") {
		t.Fatalf("expected no inline public key material in discovery JSON, got %s", out)
	}
}

func TestBuildDiscovery_APIVersion140(t *testing.T) {
	t.Parallel()

	disc := discovery.BuildDiscovery(discovery.BuildParams{
		EndPoint:   "https://example.com/ocm",
		WebDAVRoot: "/webdav/ocm/",
	}, nil)
	if disc.APIVersion != "1.4.0" {
		t.Errorf("APIVersion = %q, want 1.4.0", disc.APIVersion)
	}
}

func TestBuildDiscovery_ProtocolInventory(t *testing.T) {
	t.Parallel()

	disc := discovery.BuildDiscovery(discovery.BuildParams{
		EndPoint:         "https://example.com/ocm",
		WebDAVRoot:       "/webdav/ocm/",
		WebDAVReceiveURI: "relative",
	}, nil)

	protocols := disc.ResourceTypes[0].Protocols

	keys := sortedProtocolKeys(protocols)

	want := []string{"webdav", "webdav-receive"}
	if !slices.Equal(keys, want) {
		t.Fatalf("protocol keys = %v, want %v", keys, want)
	}
}

func TestBuildDiscovery_DisabledWhenRelativePathEndPoint(t *testing.T) {
	t.Parallel()

	disc := discovery.BuildDiscovery(discovery.BuildParams{
		EndPoint:   "/ocm",
		WebDAVRoot: "/webdav/ocm/",
	}, nil)
	if disc.Enabled {
		t.Error("expected Enabled=false for relative path endPoint")
	}
}

func TestBuildDiscovery_DisabledWhenNoScheme(t *testing.T) {
	t.Parallel()

	disc := discovery.BuildDiscovery(discovery.BuildParams{
		EndPoint:   "//example.com/ocm",
		WebDAVRoot: "/webdav/ocm/",
	}, nil)
	if disc.Enabled {
		t.Error("expected Enabled=false for endPoint without scheme")
	}
}

func TestBuildDiscovery_DisabledWhenNoHost(t *testing.T) {
	t.Parallel()

	disc := discovery.BuildDiscovery(discovery.BuildParams{
		EndPoint:   "https:///ocm",
		WebDAVRoot: "/webdav/ocm/",
	}, nil)
	if disc.Enabled {
		t.Error("expected Enabled=false for endPoint without host")
	}
}

func TestBuildDiscovery_DisabledWhenEndPointNotAbsolute(t *testing.T) {
	t.Parallel()

	disc := discovery.BuildDiscovery(discovery.BuildParams{
		EndPoint:   "/ocm",
		WebDAVRoot: "/webdav/ocm/",
	}, nil)
	if disc.Enabled {
		t.Error("expected Enabled=false for a non-absolute endPoint")
	}
}

func TestBuildDiscovery_StrictDocument(t *testing.T) {
	t.Parallel()

	webdavRoot := "/webdav/ocm/"
	disc := discovery.BuildDiscovery(discovery.BuildParams{
		EndPoint:               "https://example.com/ocm",
		WebDAVRoot:             webdavRoot,
		WebDAVReceiveURI:       "relative",
		TokenEndPoint:          "https://example.com/ocm/token",
		AdvertiseHTTPSig:       true,
		TokenExchangeCapable:   true,
		RequiresTokenExchange:  true,
		RequiresHTTPSignatures: true,
	}, nil)

	if disc.APIVersion != "1.4.0" {
		t.Errorf("APIVersion = %q, want 1.4.0", disc.APIVersion)
	}

	if !disc.Enabled {
		t.Fatal("expected Enabled=true")
	}

	if disc.EndPoint != "https://example.com/ocm" {
		t.Errorf("EndPoint = %q, want an absolute URL", disc.EndPoint)
	}

	assertSameEndpointAuthority(t, disc)
	assertStrictCapabilities(t, disc)
	assertStrictResourceTypes(t, disc)
	assertStrictProtocols(t, disc, webdavRoot)
}

// assertSameEndpointAuthority checks TokenEndPoint shares the EndPoint authority.
func assertSameEndpointAuthority(t *testing.T, disc *spec.Discovery) {
	t.Helper()

	endpointURL, err := url.Parse(disc.EndPoint)
	if err != nil {
		t.Fatalf("parse EndPoint: %v", err)
	}

	tokenURL, err := url.Parse(disc.TokenEndPoint)
	if err != nil {
		t.Fatalf("parse TokenEndPoint: %v", err)
	}

	if tokenURL.Scheme != endpointURL.Scheme || tokenURL.Host != endpointURL.Host {
		t.Errorf("TokenEndPoint authority = %q, want same authority as EndPoint %q", disc.TokenEndPoint, disc.EndPoint)
	}
}

// assertStrictCapabilities checks the capability and criteria sets of a strict
// discovery document.
func assertStrictCapabilities(t *testing.T, disc *spec.Discovery) {
	t.Helper()

	if !disc.HasCapability("http-sig") {
		t.Error("expected http-sig capability")
	}

	if !disc.HasCapability("exchange-token") {
		t.Error("expected exchange-token capability")
	}

	if !disc.HasCriteria(spec.CriteriaMustUseHTTPSig) {
		t.Error("expected must-use-http-sig criterion")
	}

	if !disc.HasCriteria(spec.CriteriaMustExchangeToken) {
		t.Error("expected must-exchange-token criterion")
	}
}

// assertStrictResourceTypes checks the file-only resource type row of a strict
// discovery document.
func assertStrictResourceTypes(t *testing.T, disc *spec.Discovery) {
	t.Helper()

	if len(disc.ResourceTypes) != 1 {
		t.Fatalf("ResourceTypes = %+v, want file only", disc.ResourceTypes)
	}

	if disc.ResourceTypes[0].Name != "file" {
		t.Errorf("ResourceTypes[0].Name = %q, want file", disc.ResourceTypes[0].Name)
	}

	if len(disc.ResourceTypes[0].ShareTypes) != 1 || disc.ResourceTypes[0].ShareTypes[0] != "user" {
		t.Errorf("ResourceTypes[0].ShareTypes = %v, want [user]", disc.ResourceTypes[0].ShareTypes)
	}
}

func TestBuildDiscovery_AdvertisesFileOnlyResourceType(t *testing.T) {
	t.Parallel()

	disc := discovery.BuildDiscovery(discovery.BuildParams{
		EndPoint:   "https://example.com/ocm",
		WebDAVRoot: "/webdav/ocm/",
	}, nil)

	if len(disc.ResourceTypes) != 1 {
		t.Fatalf("ResourceTypes = %+v, want exactly one entry", disc.ResourceTypes)
	}

	if disc.ResourceTypes[0].Name != "file" {
		t.Errorf("ResourceTypes[0].Name = %q, want file", disc.ResourceTypes[0].Name)
	}
}

// assertStrictProtocols checks the protocol map of a strict discovery
// document: sorted keys and the webdav/webdav-receive arms.
func assertStrictProtocols(t *testing.T, disc *spec.Discovery, webdavRoot string) {
	t.Helper()

	protocols := disc.ResourceTypes[0].Protocols

	keys := sortedProtocolKeys(protocols)

	wantKeys := []string{"webdav", "webdav-receive"}
	if !slices.Equal(keys, wantKeys) {
		t.Fatalf("protocol keys = %v, want %v", keys, wantKeys)
	}

	webdav, ok := protocols.StringRole("webdav")
	if !ok || webdav != webdavRoot {
		t.Fatalf("webdav = %q, ok=%v, want uri=%s", webdav, ok, webdavRoot)
	}

	wr, ok := protocols.WebDAVReceive()
	if !ok || wr.URI != spec.WebDAVReceiveURIRelative {
		t.Fatalf("webdav-receive = %+v, ok=%v, want uri=relative", wr, ok)
	}
}
