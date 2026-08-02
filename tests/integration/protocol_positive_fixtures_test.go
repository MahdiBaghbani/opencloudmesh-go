// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package integration

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
	"github.com/MahdiBaghbani/opencloudmesh-go/tests/integration/harness"
)

func fetchDiscovery(t *testing.T, srv *harness.SubprocessServer) spec.Discovery {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.BaseURL+"/.well-known/ocm", nil)
	if err != nil {
		t.Fatalf("%s build discovery request: %v", srv.Name, err)
	}

	resp, err := srv.Client().Do(req) //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	if err != nil {
		srv.DumpLogs(t)
		t.Fatalf("%s discovery GET: %v", srv.Name, err)
	}
	defer tshttp.MustClose(t, resp.Body)

	if resp.StatusCode != http.StatusOK {
		srv.DumpLogs(t)
		t.Fatalf("%s discovery status = %d, want 200", srv.Name, resp.StatusCode)
	}

	var disc spec.Discovery
	if err := json.NewDecoder(resp.Body).Decode(&disc); err != nil {
		t.Fatalf("%s decode discovery: %v", srv.Name, err)
	}

	return disc
}

func assertStrictLiveDiscovery(t *testing.T, serverName string, disc spec.Discovery, baseURL string) {
	t.Helper()

	assertStrictDiscoveryBasics(t, serverName, disc, baseURL)
	assertStrictDiscoveryCapabilities(t, serverName, disc)
	assertStrictDiscoveryFileResource(t, serverName, disc)
}

// assertStrictDiscoveryBasics checks core fields and endpoint authority.
func assertStrictDiscoveryBasics(t *testing.T, serverName string, disc spec.Discovery, baseURL string) {
	t.Helper()

	if disc.APIVersion != "1.4.0" {
		t.Fatalf("%s apiVersion = %q, want 1.4.0", serverName, disc.APIVersion)
	}

	if !disc.Enabled {
		t.Fatalf("%s discovery disabled", serverName)
	}

	if disc.EndPoint == "" || disc.TokenEndPoint == "" {
		t.Fatalf("%s discovery missing endPoint or tokenEndPoint", serverName)
	}

	assertAbsoluteSameAuthority(t, serverName, disc.EndPoint, disc.TokenEndPoint)
	assertDiscoveryEndpointsMatchServerAuthority(t, serverName, disc, baseURL)
}

// assertStrictDiscoveryCapabilities checks the strict capability and criteria set.
func assertStrictDiscoveryCapabilities(t *testing.T, serverName string, disc spec.Discovery) {
	t.Helper()

	if !disc.HasCapability("http-sig") {
		t.Fatalf("%s capabilities missing http-sig: %v", serverName, disc.Capabilities)
	}

	if !disc.HasCapability("exchange-token") {
		t.Fatalf("%s capabilities missing exchange-token: %v", serverName, disc.Capabilities)
	}

	if !disc.HasCriteria(spec.CriteriaMustUseHTTPSig) {
		t.Fatalf("%s criteria missing %s: %v", serverName, spec.CriteriaMustUseHTTPSig, disc.Criteria)
	}

	if !disc.HasCriteria(spec.CriteriaMustExchangeToken) {
		t.Fatalf("%s criteria missing %s: %v", serverName, spec.CriteriaMustExchangeToken, disc.Criteria)
	}
}

// assertStrictDiscoveryFileResource checks the file resource type protocols.
func assertStrictDiscoveryFileResource(t *testing.T, serverName string, disc spec.Discovery) {
	t.Helper()

	fileRT, ok := findResourceType(disc, "file")
	if !ok {
		t.Fatalf("%s discovery missing file resource type", serverName)
	}

	if len(fileRT.ShareTypes) != 1 || fileRT.ShareTypes[0] != "user" {
		t.Fatalf("%s file shareTypes = %v, want [user]", serverName, fileRT.ShareTypes)
	}

	webdavRole, ok := fileRT.Protocols.StringRole("webdav")
	if !ok || webdavRole == "" {
		t.Fatalf("%s file protocols missing webdav sending role", serverName)
	}

	wr, ok := fileRT.Protocols.WebDAVReceive()
	if !ok {
		t.Fatalf("%s file protocols missing webdav-receive role", serverName)
	}

	if wr.URI != spec.WebDAVReceiveURIRelative {
		t.Fatalf("%s webdav-receive uri = %q, want relative", serverName, wr.URI)
	}
}

func assertDiscoveryEndpointsMatchServerAuthority(t *testing.T, serverName string, disc spec.Discovery, baseURL string) {
	t.Helper()

	base, err := url.Parse(baseURL)
	if err != nil {
		t.Fatalf("%s parse base URL %q: %v", serverName, baseURL, err)
	}

	if base.Scheme == "" || base.Host == "" {
		t.Fatalf("%s base URL %q missing scheme or host", serverName, baseURL)
	}

	for _, endpoint := range []struct {
		name string
		raw  string
	}{
		{name: "endPoint", raw: disc.EndPoint},
		{name: "tokenEndPoint", raw: disc.TokenEndPoint},
	} {
		parsed, err := url.Parse(endpoint.raw)
		if err != nil {
			t.Fatalf("%s parse %s %q: %v", serverName, endpoint.name, endpoint.raw, err)
		}

		if parsed.Scheme != base.Scheme {
			t.Fatalf("%s %s scheme = %q, want %q from server authority", serverName, endpoint.name, parsed.Scheme, base.Scheme)
		}

		if !strings.EqualFold(parsed.Host, base.Host) {
			t.Fatalf("%s %s host = %q, want %q from server authority", serverName, endpoint.name, parsed.Host, base.Host)
		}
	}
}

func assertAbsoluteSameAuthority(t *testing.T, serverName, endPoint, tokenEndPoint string) {
	t.Helper()

	ep, err := url.Parse(endPoint)
	if err != nil {
		t.Fatalf("%s parse endPoint %q: %v", serverName, endPoint, err)
	}

	tp, err := url.Parse(tokenEndPoint)
	if err != nil {
		t.Fatalf("%s parse tokenEndPoint %q: %v", serverName, tokenEndPoint, err)
	}

	if !ep.IsAbs() || !tp.IsAbs() {
		t.Fatalf("%s endPoint/tokenEndPoint must be absolute: %q %q", serverName, endPoint, tokenEndPoint)
	}

	if ep.Scheme != tp.Scheme || !strings.EqualFold(ep.Host, tp.Host) {
		t.Fatalf("%s endPoint and tokenEndPoint differ in authority: %q vs %q", serverName, endPoint, tokenEndPoint)
	}
}

func findResourceType(disc spec.Discovery, name string) (spec.ResourceType, bool) {
	for _, rt := range disc.ResourceTypes {
		if rt.Name == name {
			return rt, true
		}
	}

	return spec.ResourceType{}, false
}
