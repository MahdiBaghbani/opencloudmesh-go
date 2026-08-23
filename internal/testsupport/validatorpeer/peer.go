// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// Package validatorpeer is an in-process mock OCM peer for validator tests.
package validatorpeer

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
)

const (
	discoveryPath = "/.well-known/ocm"
	jwksPath      = "/ocm/jwks"
)

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
	server *httptest.Server
}

// Start launches a mock peer and registers cleanup on t.
func Start(t *testing.T, opts Options) *Peer {
	t.Helper()

	var (
		srv *httptest.Server
		km  *crypto.KeyManager
	)

	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			writeDiscovery(w, srv.URL)
		case jwksPath:
			w.Header().Set("Content-Type", "application/json")
			tshttp.WriteJSON(w, km.JWKS())
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	km = crypto.NewKeyManager("", srv.URL)
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatalf("validatorpeer: load signing key: %v", err)
	}

	km.SetWireKeyID(srv.URL + "#key1")

	parsed, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("validatorpeer: parse peer URL: %v", err)
	}

	return &Peer{
		URL:    srv.URL,
		Host:   parsed.Host,
		Signer: crypto.NewRFC9421Signer(km),
		server: srv,
	}
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

	return p.server.Client()
}

func isDiscoveryRoute(r *http.Request) bool {
	return r.URL.Path == discoveryPath
}

func writeDiscovery(w http.ResponseWriter, origin string) {
	disc := spec.Discovery{
		Enabled:       true,
		APIVersion:    spec.APIVersionPin,
		EndPoint:      origin + "/ocm",
		Provider:      "Nextcloud 28",
		ResourceTypes: []spec.ResourceType{},
		Capabilities:  []string{spec.CapabilityHTTPSig},
		Criteria:      []string{},
		JwksUri:       origin + jwksPath,
	}

	tshttp.WriteJSON(w, disc)
}
