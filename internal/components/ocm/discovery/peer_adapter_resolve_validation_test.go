// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package discovery

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peerorigin"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/jwks"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
)

func TestPeerDiscoveryAdapter_RejectsDisallowedAbsoluteURIKid(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	jwkPath := "/ocm/jwks"

	var (
		jwksURI string
		srv     *httptest.Server
	)

	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case jwkPath:
			w.Header().Set("Content-Type", "application/json")
			tshttp.MustEncodeJSON(t, w, jwks.SetFromEd25519PublicKey("ignored#key1", pub))
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

	jwksURI = srv.URL + jwkPath

	_, authority, err := jwks.AuthorityFromBaseURL(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	// http absolute kid while the resolver has no dev-mode HTTP gate.
	keyID := "http://" + authority + "#key1"

	outboundCfg := &config.OutboundHTTPConfig{
		SSRF:               config.SSRFConfig{Mode: "off"},
		MaxResponseBytes:   1 << 20,
		InsecureSkipVerify: false,
	}
	rawClient := httpclient.New(outboundCfg, nil)
	discClient := NewClient(rawClient, nil)
	adapter := NewPeerDiscoveryAdapter(rawClient, discClient)
	adapter.SetPeerOrigin(peerorigin.NewResolver(false))

	_, err = adapter.ResolveVerificationKey(context.Background(), keyID)
	if err == nil {
		t.Fatal("expected absolute http keyId to be rejected when AllowHTTP is false")
	}
}

// TestNewPeerDiscoveryAdapter_JWKSResolverOptionsAreBoundedAndNonZero pins the
// production adapter constructor to a bounded, non-zero JWKS cache and fetch
// policy so this path never regresses to unbounded fetch.
func TestNewPeerDiscoveryAdapter_JWKSResolverOptionsAreBoundedAndNonZero(t *testing.T) {
	outboundCfg := &config.OutboundHTTPConfig{
		SSRF:               config.SSRFConfig{Mode: "off"},
		MaxResponseBytes:   1 << 20,
		InsecureSkipVerify: false,
	}
	rawClient := httpclient.New(outboundCfg, nil)
	discClient := NewClient(rawClient, nil)
	adapter := NewPeerDiscoveryAdapter(rawClient, discClient)

	opts, ok := adapter.JWKSResolverOptions()
	if !ok {
		t.Fatal("expected adapter to have a JWKS resolver")
	}

	if opts.TTL <= 0 {
		t.Errorf("JWKSResolverOptions().TTL = %v, want > 0", opts.TTL)
	}

	if opts.MinRefetchInterval <= 0 {
		t.Errorf("JWKSResolverOptions().MinRefetchInterval = %v, want > 0", opts.MinRefetchInterval)
	}

	if opts.NegativeCacheTTL <= 0 {
		t.Errorf("JWKSResolverOptions().NegativeCacheTTL = %v, want > 0", opts.NegativeCacheTTL)
	}

	if opts.MaxResponseBytes <= 0 {
		t.Errorf("JWKSResolverOptions().MaxResponseBytes = %v, want > 0", opts.MaxResponseBytes)
	}
}

func TestPeerDiscoveryAdapter_ResolveVerificationKey_MissingJwksUri(t *testing.T) {
	var srv *httptest.Server

	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/ocm" {
			http.NotFound(w, r)

			return
		}

		w.Header().Set("Content-Type", "application/json")
		tshttp.MustEncodeJSON(t, w, spec.Discovery{
			Enabled:    true,
			APIVersion: "1.4.0",
			EndPoint:   srv.URL + "/ocm",
		})
	}))
	defer srv.Close()

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
		t.Fatal("expected error when discovery lacks jwksUri")
	}

	if strings.Contains(err.Error(), "no jwksUri advertised") {
		return
	}

	t.Fatalf("error = %v, want no jwksUri advertised", err)
}

func TestPeerDiscoveryAdapter_ResolveVerificationKey_BlocksInvalidAdvertisedJwksUri(t *testing.T) {
	cases := []struct {
		name    string
		jwksURI string
		wantErr string
	}{
		{"cross-authority", "https://other.example.com/ocm/jwks", "jwksUri authority must match discovery origin"},
		{"credential-bearing", "", "jwksUri must not contain credentials"},
		{"fragment-bearing", "", "jwksUri must not contain a fragment"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var (
				jwksURI string
				srv     *httptest.Server
			)

			srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/.well-known/ocm" {
					http.NotFound(w, r)

					return
				}

				w.Header().Set("Content-Type", "application/json")
				tshttp.MustEncodeJSON(t, w, spec.Discovery{
					Enabled:    true,
					APIVersion: "1.4.0",
					EndPoint:   srv.URL + "/ocm",
					JwksUri:    jwksURI,
				})
			}))
			defer srv.Close()

			switch tc.name {
			case "credential-bearing":
				jwksURI = strings.Replace(srv.URL, "://", "://user:pass@", 1) + "/ocm/jwks"
			case "fragment-bearing":
				jwksURI = srv.URL + "/ocm/jwks#key-1"
			default:
				jwksURI = tc.jwksURI
			}

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
				t.Fatalf("expected error for %s advertised jwksUri", tc.name)
			}

			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}
