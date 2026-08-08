// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package discovery

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peerorigin"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/jwks"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/keyid"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigalg"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
)

func TestPeerDiscoveryAdapter_GetPublicKeyFromJWKS(t *testing.T) {
	t.Parallel()

	var (
		srv     *httptest.Server
		km      *crypto.KeyManager
		jwksURI string
	)

	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ocm/jwks":
			w.Header().Set("Content-Type", "application/json")
			tshttp.MustEncodeJSON(t, w, km.JWKS())
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

	km = crypto.NewKeyManager("", srv.URL)
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatal(err)
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

	keyID := km.GetKeyID()

	parsed, err := keyid.ParseKid(keyID)
	if err != nil {
		t.Fatalf("ParseKid(%q): %v", keyID, err)
	}

	if parsed.Scheme != "" {
		t.Fatalf("expected canonical host#fragment kid, got scheme %q in %q", parsed.Scheme, keyID)
	}

	resolved, err := adapter.ResolveVerificationKey(context.Background(), keyID)
	if err != nil {
		t.Fatalf("ResolveVerificationKey: %v", err)
	}

	if resolved.JWKAlg != "Ed25519" {
		t.Fatalf("JWKAlg = %q, want Ed25519", resolved.JWKAlg)
	}

	pub, ok := resolved.PublicKey.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("PublicKey type %T", resolved.PublicKey)
	}

	if !pub.Equal(km.GetSigningKey().PublicKey) {
		t.Fatal("JWKS public key mismatch")
	}
}

func TestPeerDiscoveryAdapter_ResolveVerificationKey_ECP256OmitAlg(t *testing.T) {
	t.Parallel()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	x := base64.RawURLEncoding.EncodeToString(padCoord(priv.X.Bytes(), 32))
	y := base64.RawURLEncoding.EncodeToString(padCoord(priv.Y.Bytes(), 32))

	var (
		keyID   string
		srv     *httptest.Server
		jwksURI string
	)

	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ocm/jwks":
			w.Header().Set("Content-Type", "application/json")
			tshttp.MustEncodeJSON(t, w, jwks.Set{Keys: []jwks.Key{{
				Kty: "EC", Kid: keyID, Use: "sig", Crv: "P-256", X: x, Y: y,
			}}})
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

	_, authority, err := jwks.AuthorityFromBaseURL(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	keyID = authority + "#ec1"

	outboundCfg := &config.OutboundHTTPConfig{
		SSRF:               config.SSRFConfig{Mode: "off"},
		MaxResponseBytes:   1 << 20,
		InsecureSkipVerify: false,
	}
	rawClient := httpclient.New(outboundCfg, nil)
	discClient := NewClient(rawClient, nil)
	adapter := NewPeerDiscoveryAdapter(rawClient, discClient)
	adapter.SetPeerOrigin(peerorigin.NewResolver(true))

	_, err = adapter.ResolveVerificationKey(context.Background(), keyID)
	if err == nil {
		t.Fatal("ResolveVerificationKey: expected error for JWK missing alg, got nil")
	}

	if !errors.Is(err, sigalg.ErrMissingAlgorithm) {
		t.Fatalf("ResolveVerificationKey error = %v, want ErrMissingAlgorithm", err)
	}
}

func TestPeerDiscoveryAdapter_ResolveVerificationKey_SchemeFromPeerContract(t *testing.T) {
	t.Parallel()

	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	var (
		keyID     string
		sawScheme string
		srv       *httptest.Server
		jwksURI   string
	)

	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ocm/jwks":
			if r.TLS == nil {
				sawScheme = "http"
			}

			w.Header().Set("Content-Type", "application/json")
			tshttp.MustEncodeJSON(t, w, jwks.SetFromEd25519PublicKey(keyID, pub))
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

	_, authority, err := jwks.AuthorityFromBaseURL(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	// Host#fragment kids follow the dev-mode HTTP transport policy.
	keyID = authority + "#key1"

	outboundCfg := &config.OutboundHTTPConfig{
		SSRF:               config.SSRFConfig{Mode: "off"},
		MaxResponseBytes:   1 << 20,
		InsecureSkipVerify: false,
	}
	rawClient := httpclient.New(outboundCfg, nil)
	discClient := NewClient(rawClient, nil)
	adapter := NewPeerDiscoveryAdapter(rawClient, discClient)
	adapter.SetPeerOrigin(peerorigin.NewResolver(true))

	resolved, err := adapter.ResolveVerificationKey(context.Background(), keyID)
	if err != nil {
		t.Fatalf("ResolveVerificationKey: %v", err)
	}

	alg, err := sigalg.ResolveAlgorithm("", resolved.JWKKty, resolved.JWKCrv, resolved.JWKAlg)
	if err != nil {
		t.Fatalf("ResolveAlgorithm: %v", err)
	}

	if alg != sigalg.Ed25519 {
		t.Fatalf("resolved algorithm = %q, want %q", alg, sigalg.Ed25519)
	}

	if sawScheme != "http" {
		t.Fatalf("JWKS transport = %q, want http in dev mode for host#fragment kid", sawScheme)
	}
}

func TestPeerDiscoveryAdapter_ResolveVerificationKey_PreservesExplicitHTTPSKid(t *testing.T) {
	t.Parallel()

	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	var (
		keyID     string
		sawScheme string
		srv       *httptest.Server
		jwksURI   string
	)

	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ocm/jwks":
			if r.TLS != nil {
				sawScheme = "https"
			}

			w.Header().Set("Content-Type", "application/json")
			tshttp.MustEncodeJSON(t, w, jwks.SetFromEd25519PublicKey(keyID, pub))
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

	_, authority, err := jwks.AuthorityFromBaseURL(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	keyID = "https://" + authority + "#key1"

	outboundCfg := &config.OutboundHTTPConfig{
		SSRF:               config.SSRFConfig{Mode: "off"},
		MaxResponseBytes:   1 << 20,
		InsecureSkipVerify: true,
	}
	rawClient := httpclient.New(outboundCfg, nil)
	discClient := NewClient(rawClient, nil)
	adapter := NewPeerDiscoveryAdapter(rawClient, discClient)
	adapter.SetPeerOrigin(peerorigin.NewResolver(true))

	resolved, err := adapter.ResolveVerificationKey(context.Background(), keyID)
	if err != nil {
		t.Fatalf("ResolveVerificationKey: %v", err)
	}

	alg, err := sigalg.ResolveAlgorithm("", resolved.JWKKty, resolved.JWKCrv, resolved.JWKAlg)
	if err != nil {
		t.Fatalf("ResolveAlgorithm: %v", err)
	}

	if alg != sigalg.Ed25519 {
		t.Fatalf("resolved algorithm = %q, want %q", alg, sigalg.Ed25519)
	}

	if sawScheme != "https" {
		t.Fatalf("JWKS transport = %q, want https for absolute https kid", sawScheme)
	}
}
