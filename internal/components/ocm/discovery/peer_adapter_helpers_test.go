// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package discovery

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
)

func padCoord(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}

	out := make([]byte, size)
	copy(out[size-len(b):], b)

	return out
}

// newJWKSErrorPeer starts a mock peer whose discovery document points at its
// own JWKS path; the JWKS path itself is served by jwksHandler.
func newJWKSErrorPeer(t *testing.T, jwksHandler http.HandlerFunc) *httptest.Server {
	t.Helper()

	var srv *httptest.Server

	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ocm/jwks":
			jwksHandler(w, r)
		case "/.well-known/ocm":
			w.Header().Set("Content-Type", "application/json")
			tshttp.MustEncodeJSON(t, w, spec.Discovery{
				Enabled:    true,
				APIVersion: "1.4.0",
				EndPoint:   srv.URL + "/ocm",
				JwksUri:    srv.URL + "/ocm/jwks",
			})
		default:
			http.NotFound(w, r)
		}
	}))

	return srv
}

// newLoadedKeyManager creates a key manager for the peer URL and loads or
// generates its key material.
func newLoadedKeyManager(t *testing.T, peerURL string) *crypto.KeyManager {
	t.Helper()

	km := crypto.NewKeyManager("", peerURL)
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatal(err)
	}

	return km
}

// expectResolveKeyError asserts that resolving the manager's key against the
// adapter fails.
func expectResolveKeyError(t *testing.T, adapter *PeerDiscoveryAdapter, km *crypto.KeyManager, msg string) {
	t.Helper()

	_, err := adapter.ResolveVerificationKey(context.Background(), km.GetKeyID())
	if err == nil {
		t.Fatal(msg)
	}
}
