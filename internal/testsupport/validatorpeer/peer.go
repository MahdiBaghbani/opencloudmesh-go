// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// Package validatorpeer is an in-process mock OCM peer for validator tests.
package validatorpeer

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
)

const (
	discoveryPath = "/.well-known/ocm"
	jwksPath      = "/ocm/jwks"

	// HostName is the advertised peer hostname in Peer.URL and Peer.Host.
	HostName = "validator-peer.test"

	loopbackIP = "127.0.0.1"
)

// DialHosts returns the test-only hostname-to-IP map for the shared outbound
// client so advertised HostName requests reach the httptest listener.
func DialHosts() map[string]string {
	return map[string]string{
		HostName: loopbackIP,
	}
}

// Options configures a mock peer.
type Options struct {
	// FailDiscovery makes /.well-known/ocm return HTTP 500.
	FailDiscovery bool
}

// Peer is a TLS mock OCM peer with discovery and JWKS.
type Peer struct {
	URL    string
	Host   string
	Signer *crypto.RFC9421Signer
	Hits   atomic.Int32
	server *httptest.Server
}

// Start launches a mock peer and registers cleanup on t.
func Start(t *testing.T, opts Options) *Peer {
	t.Helper()

	var (
		srv *httptest.Server
		km  *crypto.KeyManager
	)

	var advertised string

	peer := &Peer{}

	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peer.Hits.Add(1)

		if opts.FailDiscovery && isDiscoveryRoute(r) {
			http.Error(w, "discovery failed", http.StatusInternalServerError)

			return
		}

		if km == nil {
			http.Error(w, "peer signing key not initialized", http.StatusServiceUnavailable)

			return
		}

		switch r.URL.Path {
		case discoveryPath:
			writeDiscovery(w, advertised)
		case jwksPath:
			w.Header().Set("Content-Type", "application/json")
			tshttp.WriteJSON(w, km.JWKS())
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	host, origin, err := advertisedPeer(srv.URL)
	if err != nil {
		t.Fatalf("validatorpeer: advertise peer URL: %v", err)
	}

	advertised = origin

	km = crypto.NewKeyManager("", advertised)
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatalf("validatorpeer: load signing key: %v", err)
	}

	km.SetWireKeyID(advertised + "#key1")

	peer.URL = advertised
	peer.Host = host
	peer.Signer = crypto.NewRFC9421Signer(km)
	peer.server = srv

	return peer
}

// Close shuts down the mock peer listener.
func (p *Peer) Close() {
	if p != nil && p.server != nil {
		p.server.Close()
	}
}

// HTTPClient returns a client that trusts this peer's TLS certificate.
func (p *Peer) HTTPClient() *http.Client {
	if p == nil || p.server == nil {
		return http.DefaultClient
	}

	base := p.server.Client()

	transport, ok := base.Transport.(*http.Transport)
	if !ok {
		return base
	}

	cloned := transport.Clone()
	listener := p.server.Listener.Addr().String()
	cloned.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, listener)
	}

	if cloned.TLSClientConfig != nil {
		// httptest certs are issued for the listener IP; Peer.URL advertises HostName.
		cloned.TLSClientConfig.ServerName = listenerHostname(p.server)
	}

	return &http.Client{
		Transport:     cloned,
		CheckRedirect: base.CheckRedirect,
		Jar:           base.Jar,
		Timeout:       base.Timeout,
	}
}

func advertisedPeer(listenerURL string) (host, origin string, err error) {
	parsed, err := url.Parse(listenerURL)
	if err != nil {
		return "", "", fmt.Errorf("validatorpeer: parse listener URL: %w", err)
	}

	host = net.JoinHostPort(HostName, parsed.Port())
	origin = (&url.URL{Scheme: parsed.Scheme, Host: host}).String()

	return host, origin, nil
}

func listenerHostname(srv *httptest.Server) string {
	if srv == nil {
		return loopbackIP
	}

	parsed, err := url.Parse(srv.URL)
	if err != nil || parsed.Hostname() == "" {
		return loopbackIP
	}

	return parsed.Hostname()
}

func isDiscoveryRoute(r *http.Request) bool {
	return r.URL.Path == discoveryPath
}

func writeDiscovery(w http.ResponseWriter, origin string) {
	// advertisedPeer replaces the origin host with HostName whenever the URL
	// parses, matching Peer.URL. Invalid origins keep the supplied string.
	advertised := origin
	if _, rewritten, err := advertisedPeer(origin); err == nil {
		advertised = rewritten
	}

	disc := spec.Discovery{
		Enabled:       true,
		APIVersion:    spec.APIVersionPin,
		EndPoint:      advertised + "/ocm",
		Provider:      "Nextcloud 28",
		ResourceTypes: []spec.ResourceType{},
		Capabilities:  []string{spec.CapabilityHTTPSig},
		Criteria:      []string{},
		JwksUri:       advertised + jwksPath,
	}

	tshttp.WriteJSON(w, disc)
}
