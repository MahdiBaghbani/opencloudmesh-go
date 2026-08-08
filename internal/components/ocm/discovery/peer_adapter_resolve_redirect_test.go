// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package discovery

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peerorigin"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/jwks"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
)

func TestPeerDiscoveryAdapter_ResolveVerificationKey_BlocksHTTPSDowngradeRedirect(t *testing.T) {
	t.Parallel()

	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	var (
		jwksURI string
		srv     *httptest.Server
	)

	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ocm/jwks":
			w.Header().Set("Location", strings.Replace(srv.URL, "https://", "http://", 1)+"/ocm/jwks")
			w.WriteHeader(http.StatusFound)
		case "/.well-known/ocm":
			w.Header().Set("Content-Type", "application/json")
			tshttp.MustEncodeJSON(t, w, spec.Discovery{
				Enabled:    true,
				APIVersion: "1.4.0",
				EndPoint:   srv.URL + "/ocm",
				JwksUri:    jwksURI,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	jwksURI = srv.URL + "/ocm/jwks"

	outboundCfg := &config.OutboundHTTPConfig{
		SSRF:               config.SSRFConfig{Mode: "off"},
		MaxResponseBytes:   1 << 20,
		InsecureSkipVerify: true,
	}
	rawClient := httpclient.New(outboundCfg, nil)
	discClient := NewClient(rawClient, nil)
	adapter := NewPeerDiscoveryAdapter(rawClient, discClient)
	adapter.SetPeerOrigin(peerorigin.NewResolver(false))

	_, authority, err := jwks.AuthorityFromBaseURL(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	keyID := authority + "#key1"

	// Silence unused pub warning.
	_ = pub

	_, err = adapter.ResolveVerificationKey(context.Background(), keyID)
	if err == nil {
		t.Fatal("expected error for HTTPS-to-HTTP downgrade redirect")
	}

	if !errors.Is(err, httpclient.ErrRedirectDowngrade) {
		t.Fatalf("error = %v, want errors.Is(..., httpclient.ErrRedirectDowngrade)", err)
	}
}

func TestPeerDiscoveryAdapter_ResolveVerificationKey_BlocksCrossHostRedirect(t *testing.T) {
	t.Parallel()

	var (
		jwksURI string
		srv     *httptest.Server
	)

	redirectLocation := ""

	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ocm/jwks":
			w.Header().Set("Location", redirectLocation)
			w.WriteHeader(http.StatusFound)
		case "/.well-known/ocm":
			w.Header().Set("Content-Type", "application/json")
			tshttp.MustEncodeJSON(t, w, spec.Discovery{
				Enabled:    true,
				APIVersion: "1.4.0",
				EndPoint:   srv.URL + "/ocm",
				JwksUri:    jwksURI,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	u, parseErr := url.Parse(srv.URL)
	if parseErr != nil {
		t.Fatalf("parse test server URL: %v", parseErr)
	}

	otherPort, portErr := strconv.Atoi(u.Port())
	if portErr != nil {
		t.Fatalf("parse test server port: %v", portErr)
	}

	redirectLocation = "http://" + net.JoinHostPort(u.Hostname(), strconv.Itoa(otherPort+1)) + "/ocm/jwks"
	jwksURI = srv.URL + "/ocm/jwks"

	outboundCfg := &config.OutboundHTTPConfig{
		SSRF:               config.SSRFConfig{Mode: "off"},
		MaxResponseBytes:   1 << 20,
		InsecureSkipVerify: false,
	}
	rawClient := httpclient.New(outboundCfg, nil)
	discClient := NewClient(rawClient, nil)
	adapter := NewPeerDiscoveryAdapter(rawClient, discClient)
	adapter.SetPeerOrigin(peerorigin.NewResolver(true))

	_, authority, err := jwks.AuthorityFromBaseURL(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	keyID := authority + "#key1"

	_, err = adapter.ResolveVerificationKey(context.Background(), keyID)
	if err == nil {
		t.Fatal("expected error for cross-host redirect")
	}

	if !errors.Is(err, httpclient.ErrRedirectNotSameHost) {
		t.Fatalf("error = %v, want errors.Is(..., httpclient.ErrRedirectNotSameHost)", err)
	}
}
