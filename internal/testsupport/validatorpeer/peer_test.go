// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorpeer

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
)

func TestStart_ServesDiscoveryAndJWKS(t *testing.T) {
	t.Parallel()

	peer := Start(t, Options{})
	client := peer.HTTPClient()

	status, raw := getBytes(t, client, peer.URL+discoveryPath)
	if status != http.StatusOK {
		t.Fatalf("discovery status = %d, want 200", status)
	}

	var disc spec.Discovery
	if err := json.Unmarshal(raw, &disc); err != nil {
		t.Fatalf("decode discovery: %v", err)
	}

	if !disc.Enabled {
		t.Fatal("expected enabled discovery")
	}

	if disc.APIVersion != spec.APIVersionPin {
		t.Fatalf("apiVersion = %q, want %q", disc.APIVersion, spec.APIVersionPin)
	}

	assertAdvertisedHostname(t, peer, disc)

	jwksStatus, _ := getBytes(t, client, peer.URL+jwksPath)
	if jwksStatus != http.StatusOK {
		t.Fatalf("jwks status = %d, want 200", jwksStatus)
	}

	if peer.Host == "" || peer.Signer == nil {
		t.Fatal("expected host and signer")
	}
}

func TestStart_FailDiscoveryReturns500(t *testing.T) {
	t.Parallel()

	peer := Start(t, Options{FailDiscovery: true})
	client := peer.HTTPClient()

	status, _ := getBytes(t, client, peer.URL+discoveryPath)
	if status != http.StatusInternalServerError {
		t.Fatalf("discovery status = %d, want 500", status)
	}

	jwksStatus, _ := getBytes(t, client, peer.URL+jwksPath)
	if jwksStatus != http.StatusOK {
		t.Fatalf("jwks status = %d, want 200", jwksStatus)
	}

	otherStatus, _ := getBytes(t, client, peer.URL+"/not-discovery")
	if otherStatus != http.StatusNotFound {
		t.Fatalf("other status = %d, want 404", otherStatus)
	}
}

func TestDialHosts_MapsAdvertisedNameToLoopback(t *testing.T) {
	t.Parallel()

	got := DialHosts()
	if got[HostName] != loopbackIP {
		t.Fatalf("DialHosts()[%q] = %q, want %q", HostName, got[HostName], loopbackIP)
	}
}

func TestWriteDiscovery_RewritesLoopbackListenerOrigins(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		origin string
	}{
		{name: "ipv4 loopback", origin: "https://127.0.0.1:8443"},
		{name: "ipv6 loopback", origin: "https://[::1]:8443"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rec := httptest.NewRecorder()
			writeDiscovery(rec, tc.origin)

			var disc spec.Discovery
			if err := json.Unmarshal(rec.Body.Bytes(), &disc); err != nil {
				t.Fatalf("decode discovery: %v", err)
			}

			assertDiscoveryAdvertisesHostName(t, disc, "8443")
		})
	}
}

func TestAdvertisedPeer_RewritesIPv6LoopbackListener(t *testing.T) {
	t.Parallel()

	host, origin, err := advertisedPeer("https://[::1]:8443")
	if err != nil {
		t.Fatalf("advertisedPeer: %v", err)
	}

	wantHost := net.JoinHostPort(HostName, "8443")
	if host != wantHost {
		t.Fatalf("host = %q, want %q", host, wantHost)
	}

	if strings.Contains(origin, "127.0.0.1") || strings.Contains(origin, "::1") {
		t.Fatalf("origin %q must not advertise the listener IP", origin)
	}

	parsed, err := url.Parse(origin)
	if err != nil {
		t.Fatalf("parse origin: %v", err)
	}

	if parsed.Hostname() != HostName {
		t.Fatalf("origin hostname = %q, want %q", parsed.Hostname(), HostName)
	}
}

func assertAdvertisedHostname(t *testing.T, peer *Peer, disc spec.Discovery) {
	t.Helper()

	parsed, err := url.Parse(peer.URL)
	if err != nil {
		t.Fatalf("parse advertised URL: %v", err)
	}

	if parsed.Hostname() != HostName {
		t.Fatalf("Peer.URL hostname = %q, want %q", parsed.Hostname(), HostName)
	}

	if strings.Contains(peer.URL, "127.0.0.1") || strings.Contains(peer.URL, "::1") {
		t.Fatalf("Peer.URL %q must not advertise the httptest listener IP", peer.URL)
	}

	wantHost := net.JoinHostPort(HostName, parsed.Port())
	if peer.Host != wantHost {
		t.Fatalf("Peer.Host = %q, want %q", peer.Host, wantHost)
	}

	assertDiscoveryAdvertisesHostName(t, disc, parsed.Port())
}

func assertDiscoveryAdvertisesHostName(t *testing.T, disc spec.Discovery, port string) {
	t.Helper()

	if !strings.Contains(disc.EndPoint, HostName) {
		t.Fatalf("discovery endpoint %q must contain %q", disc.EndPoint, HostName)
	}

	if strings.Contains(disc.EndPoint, "127.0.0.1") || strings.Contains(disc.EndPoint, "::1") {
		t.Fatalf("discovery endpoint %q must not advertise a loopback listener IP", disc.EndPoint)
	}

	if strings.Contains(disc.JwksUri, "127.0.0.1") || strings.Contains(disc.JwksUri, "::1") {
		t.Fatalf("discovery jwks %q must not advertise a loopback listener IP", disc.JwksUri)
	}

	jwks, err := url.Parse(disc.JwksUri)
	if err != nil {
		t.Fatalf("parse jwks URI: %v", err)
	}

	if jwks.Hostname() != HostName {
		t.Fatalf("JwksUri hostname = %q, want %q", jwks.Hostname(), HostName)
	}

	if port != "" && jwks.Port() != port {
		t.Fatalf("JwksUri port = %q, want %q", jwks.Port(), port)
	}
}

func getBytes(t *testing.T, client *http.Client, rawURL string) (int, []byte) {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatalf("build GET %s: %v", rawURL, err)
	}

	resp, err := client.Do(req) //nolint:bodyclose // closed by tshttp.MustClose; bodyclose cannot trace the helper
	if err != nil {
		t.Fatalf("GET %s: %v", rawURL, err)
	}
	defer tshttp.MustClose(t, resp.Body)

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", rawURL, err)
	}

	return resp.StatusCode, raw
}
