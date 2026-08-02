// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package jwks_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/jwks"
)

func TestResolver_ResolveURL(t *testing.T) {
	pub, _ := mustEd25519KeyPair(t)
	set := jwks.SetFromEd25519PublicKey(testJWKSKey1, pub)

	srv := httptest.NewServer(jwksJSONHandler(set))
	defer srv.Close()

	resolver, err := jwks.NewResolver(srv.Client())
	if err != nil {
		t.Fatal(err)
	}

	jwksURL := srv.URL + "/jwks"

	got, err := resolver.ResolveURL(context.Background(), jwksURL, testJWKSKey1)
	if err != nil {
		t.Fatalf("ResolveURL: %v", err)
	}

	gotPub, ok := got.PublicKey.(ed25519.PublicKey)
	if !ok {
		t.Fatal("expected ed25519 public key")
	}

	if !pub.Equal(gotPub) {
		t.Fatal("key mismatch")
	}
}

type recordingDoer struct {
	lastURL string
	body    []byte
}

func (d *recordingDoer) Do(req *http.Request) (*http.Response, error) {
	d.lastURL = req.URL.String()

	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(d.body)),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

func TestResolver_ResolveURL_HonorsExplicitURL(t *testing.T) {
	pub, _ := mustEd25519KeyPair(t)
	set := jwks.SetFromEd25519PublicKey(testJWKSKey1, pub)

	body, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}

	doer := &recordingDoer{body: body}

	resolver, err := jwks.NewResolver(doer)
	if err != nil {
		t.Fatal(err)
	}

	// OCM key ID lookup is exact (keyid == kid), so the lookup key ID
	// must equal the set kid byte-for-byte.
	got, err := resolver.ResolveURL(context.Background(), "https://example.com:443/jwks", "example.com#key1")
	if err != nil {
		t.Fatalf("ResolveURL: %v", err)
	}

	gotPub, ok := got.PublicKey.(ed25519.PublicKey)
	if !ok {
		t.Fatal("expected ed25519 public key")
	}

	if !pub.Equal(gotPub) {
		t.Fatal("key mismatch")
	}

	if doer.lastURL != "https://example.com:443/jwks" {
		t.Fatalf("fetch URL = %q, want exact advertised URL", doer.lastURL)
	}
}

func TestResolver_ResolveURL_MissingKid(t *testing.T) {
	pub, _ := mustEd25519KeyPair(t)
	set := jwks.SetFromEd25519PublicKey(testJWKSKey1, pub)

	srv := httptest.NewServer(jwksJSONHandler(set))
	defer srv.Close()

	resolver, err := jwks.NewResolver(srv.Client())
	if err != nil {
		t.Fatal(err)
	}

	_, err = resolver.ResolveURL(context.Background(), srv.URL+"/jwks", "example.com#missing")
	if !errors.Is(err, jwks.ErrKeyNotFound) {
		t.Fatalf("ResolveURL() error = %v, want ErrKeyNotFound", err)
	}
}

func TestResolver_EffectiveOptions_DefaultsAreBoundedAndNonZero(t *testing.T) {
	resolver, err := jwks.NewResolver(&recordingDoer{})
	if err != nil {
		t.Fatal(err)
	}

	opts := resolver.EffectiveOptions()

	if opts.TTL <= 0 {
		t.Errorf("EffectiveOptions().TTL = %v, want > 0", opts.TTL)
	}

	if opts.MinRefetchInterval <= 0 {
		t.Errorf("EffectiveOptions().MinRefetchInterval = %v, want > 0", opts.MinRefetchInterval)
	}

	if opts.NegativeCacheTTL <= 0 {
		t.Errorf("EffectiveOptions().NegativeCacheTTL = %v, want > 0", opts.NegativeCacheTTL)
	}

	if opts.MaxResponseBytes <= 0 {
		t.Errorf("EffectiveOptions().MaxResponseBytes = %v, want > 0", opts.MaxResponseBytes)
	}
}

func TestResolver_EffectiveOptions_ExplicitZeroFallsBackToDefaults(t *testing.T) {
	resolver, err := jwks.NewResolverWithOptions(&recordingDoer{}, jwks.ResolverOptions{})
	if err != nil {
		t.Fatal(err)
	}

	opts := resolver.EffectiveOptions()
	if opts.TTL != jwks.DefaultCacheTTL {
		t.Errorf("EffectiveOptions().TTL = %v, want default %v", opts.TTL, jwks.DefaultCacheTTL)
	}

	if opts.MinRefetchInterval != jwks.DefaultMinRefetchInterval {
		t.Errorf("EffectiveOptions().MinRefetchInterval = %v, want default %v", opts.MinRefetchInterval, jwks.DefaultMinRefetchInterval)
	}

	if opts.NegativeCacheTTL != jwks.DefaultNegativeCacheTTL {
		t.Errorf("EffectiveOptions().NegativeCacheTTL = %v, want default %v", opts.NegativeCacheTTL, jwks.DefaultNegativeCacheTTL)
	}

	if opts.MaxResponseBytes <= 0 {
		t.Errorf("EffectiveOptions().MaxResponseBytes = %v, want > 0", opts.MaxResponseBytes)
	}
}

func TestNewResolver_NilClient(t *testing.T) {
	_, err := jwks.NewResolver(nil)
	if !errors.Is(err, jwks.ErrNilHTTPClient) {
		t.Fatalf("NewResolver(nil) = %v, want ErrNilHTTPClient", err)
	}

	_, err = jwks.NewResolverWithTTL(nil, time.Minute)
	if !errors.Is(err, jwks.ErrNilHTTPClient) {
		t.Fatalf("NewResolverWithTTL(nil) = %v, want ErrNilHTTPClient", err)
	}
}
