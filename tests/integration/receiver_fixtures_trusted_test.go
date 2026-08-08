// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package integration

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/modroot"
)

// trustedProtocolPeer serves HTTPS using the shared dockypody-signed localhost
// fixture certificate so strict subprocess servers trust it via tls_root_ca_file.
type trustedProtocolPeer struct {
	t             *testing.T
	server        *http.Server
	peerDomain    string
	peerBaseURL   string
	port          int
	postCount     atomic.Int32
	discoveryHits atomic.Int32
}

func (p *trustedProtocolPeer) Close() {
	if p != nil && p.server != nil {
		if err := p.server.Close(); err != nil && p.t != nil {
			p.t.Errorf("close trusted protocol peer: %v", err)
		}
	}
}

func (p *trustedProtocolPeer) Port() int {
	if p == nil {
		return 0
	}

	return p.port
}

func (p *trustedProtocolPeer) PostCount() int32 {
	if p == nil {
		return 0
	}

	return p.postCount.Load()
}

func (p *trustedProtocolPeer) DiscoveryHits() int32 {
	if p == nil {
		return 0
	}

	return p.discoveryHits.Load()
}

func startTrustedProtocolPeer(t *testing.T, handler func(peer *trustedProtocolPeer, w http.ResponseWriter, r *http.Request)) *trustedProtocolPeer {
	t.Helper()

	moduleRoot := modroot.ModuleRoot(t)
	certFile := filepath.Join(moduleRoot, "tests", "e2e", "testdata", "tls", "localhost.crt")
	keyFile := filepath.Join(moduleRoot, "tests", "e2e", "testdata", "tls", "localhost.key")

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("load trusted protocol peer TLS key pair: %v", err)
	}

	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen trusted protocol peer: %v", err)
	}

	tcpAddr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("trusted protocol peer listener address type = %T, want *net.TCPAddr", listener.Addr())
	}

	port := tcpAddr.Port
	tlsListener := tls.NewListener(listener, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})

	peer := &trustedProtocolPeer{
		t:           t,
		port:        port,
		peerDomain:  fmt.Sprintf("localhost:%d", port),
		peerBaseURL: fmt.Sprintf("https://localhost:%d", port),
	}
	peer.server = &http.Server{ //nolint:gosec // test server: short-lived, no Slowloris risk
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/.well-known/ocm" {
				peer.discoveryHits.Add(1)
			}

			handler(peer, w, r)
		}),
	}

	go func() {
		if err := peer.server.Serve(tlsListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("trusted protocol peer serve: %v", err)
		}
	}()

	t.Cleanup(func() {
		peer.Close()
	})

	return peer
}
