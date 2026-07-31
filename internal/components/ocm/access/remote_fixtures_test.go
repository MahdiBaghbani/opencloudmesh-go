// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package access

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peerorigin"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	tokenoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token/outgoing"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
)

func newTestDiscoveryServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/ocm" {
			disc := spec.Discovery{
				Enabled:    true,
				APIVersion: "1.4.0",
				EndPoint:   "https://" + r.Host + "/ocm",
				ResourceTypes: []spec.ResourceType{
					{
						Name:       "file",
						ShareTypes: []string{"user"},
						Protocols:  spec.Protocols{"webdav": spec.StringProtocolRole("/webdav/ocm")},
					},
				},
			}

			tshttp.WriteJSON(w, disc)

			return
		}

		http.NotFound(w, r)
	}))
}

func newTestClients(_ string) (*discovery.Client, *httpclient.ContextClient) {
	cfg := tshttp.PermissiveConfig()
	cfg.InsecureSkipVerify = true
	rawClient := httpclient.New(cfg, nil)
	discClient := discovery.NewClient(rawClient, nil)
	ctxClient := httpclient.NewContextClient(rawClient)

	return discClient, ctxClient
}

type accessMockSigner struct{}

func (accessMockSigner) Sign(req *http.Request) error {
	req.Header.Set("Signature", "mock-signature")
	return nil
}

func newExchangeAccessClient(
	t *testing.T,
	srv *httptest.Server,
) *Client {
	t.Helper()

	discClient, ctxClient := newTestClients(srv.URL)
	tokenClient := tokenoutgoing.NewClient(ctxClient, accessMockSigner{}, "local.example.com")
	client := NewClient(
		ctxClient,
		discClient,
		tokenClient,
		peerorigin.NewResolver(true),
	)

	return client
}

func exchangeDiscoveryHandler(t *testing.T, w http.ResponseWriter, r *http.Request, accessToken string) bool {
	t.Helper()

	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}

	if r.URL.Path == "/.well-known/ocm" {
		disc := spec.Discovery{
			Enabled:       true,
			APIVersion:    "1.4.0",
			EndPoint:      scheme + "://" + r.Host + "/ocm",
			Capabilities:  []string{"exchange-token", "http-sig"},
			TokenEndPoint: scheme + "://" + r.Host + "/ocm/token",
			ResourceTypes: []spec.ResourceType{
				{
					Name:       "file",
					ShareTypes: []string{"user"},
					Protocols:  spec.Protocols{"webdav": spec.StringProtocolRole("/webdav/ocm")},
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		tshttp.WriteJSON(w, disc)

		return true
	}

	if r.URL.Path == "/ocm/token" {
		if r.Header.Get("Signature") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return true
		}

		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return true
		}

		w.Header().Set("Content-Type", "application/json")
		tshttp.MustWrite(t, w, []byte(`{"access_token":"`+accessToken+`","token_type":"Bearer","expires_in":3600}`))

		return true
	}

	return false
}
