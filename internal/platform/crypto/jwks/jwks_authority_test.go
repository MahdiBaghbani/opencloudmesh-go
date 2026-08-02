// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package jwks_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/jwks"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigalg"
)

func TestAuthorityFromBaseURL_NormalizesHostAndDefaultPort(t *testing.T) {
	scheme, authority, err := jwks.AuthorityFromBaseURL("https://Example.COM:443/ocm/path?q=1")
	if err != nil {
		t.Fatalf("AuthorityFromBaseURL: %v", err)
	}

	if scheme != "https" {
		t.Fatalf("scheme = %q, want https", scheme)
	}

	if authority != "example.com" {
		t.Fatalf("authority = %q, want example.com", authority)
	}

	scheme, authority, err = jwks.AuthorityFromBaseURL("http://Example.COM:80/")
	if err != nil {
		t.Fatalf("AuthorityFromBaseURL http: %v", err)
	}

	if scheme != "http" || authority != "example.com" {
		t.Fatalf("http default port = %s %q, want http example.com", scheme, authority)
	}
}

func TestEd25519Key_PublicationIncludesAlg(t *testing.T) {
	pub, _ := mustEd25519KeyPair(t)
	key := jwks.Ed25519Key(testJWKSKey1, pub)

	if key.Alg != "Ed25519" {
		t.Fatalf("Ed25519Key alg = %q, want Ed25519", key.Alg)
	}

	if key.Kty != "OKP" || key.Crv != "Ed25519" || key.Kid != testJWKSKey1 || key.Use != "sig" {
		t.Fatalf("Ed25519Key missing required fields: %+v", key)
	}

	got, err := jwks.Set{Keys: []jwks.Key{key}}.ResolveExactKeyID(testJWKSKey1)
	if err != nil {
		t.Fatalf("ResolveExactKeyID: %v", err)
	}

	if got.JWKAlg != "Ed25519" {
		t.Fatalf("resolved JWK alg = %q, want Ed25519", got.JWKAlg)
	}

	if _, ok := got.PublicKey.(ed25519.PublicKey); !ok {
		t.Fatalf("public key type %T, want ed25519.PublicKey", got.PublicKey)
	}
}

func TestResolver_ResolveURL_RejectsInvalidJWKBeforeVerifierUse(t *testing.T) {
	pub, _ := mustEd25519KeyPair(t)
	key := jwks.Ed25519Key(testJWKSKey1, pub)
	key.Alg = "ES256" // incompatible alg/kty/crv: Ed25519 key claiming ES256

	set := jwks.Set{Keys: []jwks.Key{key}}

	srv := httptest.NewServer(jwksJSONHandler(set))
	defer srv.Close()

	resolver, err := jwks.NewResolver(srv.Client())
	if err != nil {
		t.Fatal(err)
	}

	_, err = resolver.ResolveURL(context.Background(), srv.URL+"/jwks", testJWKSKey1)
	if err == nil {
		t.Fatal("expected invalid JWK to be rejected before verifier use")
	}

	if !errors.Is(err, sigalg.ErrAlgorithmMismatch) {
		t.Fatalf("error = %v, want ErrAlgorithmMismatch", err)
	}
}
