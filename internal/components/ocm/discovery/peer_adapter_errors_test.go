// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package discovery

import (
	"net/http"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peerorigin"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
)

func TestPeerDiscoveryAdapter_GetPublicKey_JWKSErrors(t *testing.T) {
	t.Parallel()

	peerOrigin := peerorigin.NewResolver(true)

	outboundCfg := &config.OutboundHTTPConfig{
		SSRF:               config.SSRFConfig{Mode: "off"},
		MaxResponseBytes:   1 << 20,
		InsecureSkipVerify: false,
	}
	rawClient := httpclient.New(outboundCfg, nil)
	discClient := NewClient(rawClient, nil)

	t.Run("jwks 404", func(t *testing.T) {
		t.Parallel()

		srv := newJWKSErrorPeer(t, http.NotFound)
		defer srv.Close()

		km := newLoadedKeyManager(t, srv.URL)
		adapter := NewPeerDiscoveryAdapter(rawClient, discClient)
		adapter.SetPeerOrigin(peerOrigin)

		expectResolveKeyError(t, adapter, km, "expected jwks lookup error for 404")
	})

	t.Run("invalid jwks JSON", func(t *testing.T) {
		t.Parallel()

		srv := newJWKSErrorPeer(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")

			if _, err := w.Write([]byte(`{"keys":[`)); err != nil {
				t.Errorf("write response: %v", err)
			}
		})
		defer srv.Close()

		km := newLoadedKeyManager(t, srv.URL)
		adapter := NewPeerDiscoveryAdapter(rawClient, discClient)
		adapter.SetPeerOrigin(peerOrigin)

		expectResolveKeyError(t, adapter, km, "expected jwks decode error")
	})

	t.Run("missing kid", func(t *testing.T) {
		t.Parallel()
		otherKM := newLoadedKeyManager(t, "https://other.example.com")

		srv := newJWKSErrorPeer(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			tshttp.MustEncodeJSON(t, w, otherKM.JWKS())
		})
		defer srv.Close()

		km := newLoadedKeyManager(t, srv.URL)
		adapter := NewPeerDiscoveryAdapter(rawClient, discClient)
		adapter.SetPeerOrigin(peerOrigin)

		expectResolveKeyError(t, adapter, km, "expected missing kid error")
	})
}
