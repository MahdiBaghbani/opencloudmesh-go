// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package jwks_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"math/big"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/jwks"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigalg"
	tscrypto "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/crypto"
)

func TestSetFromEd25519PublicKey_ResolveExactKeyID(t *testing.T) {
	pub, _ := mustEd25519KeyPair(t)

	set := jwks.SetFromEd25519PublicKey(testJWKSKey1, pub)

	got, err := set.ResolveExactKeyID(testJWKSKey1)
	if err != nil {
		t.Fatalf("ResolveExactKeyID: %v", err)
	}

	requireResolvedAlgorithm(t, got, sigalg.Ed25519)

	gotPub, ok := got.PublicKey.(ed25519.PublicKey)
	if !ok {
		t.Fatal("expected ed25519 public key")
	}

	if !pub.Equal(gotPub) {
		t.Fatal("public key mismatch")
	}
}

func TestResolveExactKeyID_MissingKid(t *testing.T) {
	pub, _ := mustEd25519KeyPair(t)
	set := jwks.SetFromEd25519PublicKey(testJWKSKey1, pub)

	_, err := set.ResolveExactKeyID("example.com#missing")
	if !errors.Is(err, jwks.ErrKeyNotFound) {
		t.Fatalf("ResolveExactKeyID() error = %v, want ErrKeyNotFound", err)
	}
}

func TestResolveExactKeyID_AmbiguousKid(t *testing.T) {
	pub, _ := mustEd25519KeyPair(t)
	set := jwks.Set{Keys: []jwks.Key{
		jwks.Ed25519Key(testJWKSKey1, pub),
		jwks.Ed25519Key(testJWKSKey1, pub),
	}}

	_, err := set.ResolveExactKeyID(testJWKSKey1)
	if !errors.Is(err, jwks.ErrAmbiguousKid) {
		t.Fatalf("ResolveExactKeyID() error = %v, want ErrAmbiguousKid", err)
	}
}

func TestResolveExactKeyID_UseSigAndEnc(t *testing.T) {
	pub, _ := mustEd25519KeyPair(t)

	sigKey := jwks.Ed25519Key(testJWKSKey1, pub)
	if sigKey.Use != "sig" {
		t.Fatalf("Ed25519Key Use = %q, want sig", sigKey.Use)
	}

	got, err := jwks.Set{Keys: []jwks.Key{sigKey}}.ResolveExactKeyID(testJWKSKey1)
	if err != nil {
		t.Fatalf("use=sig ResolveExactKeyID: %v", err)
	}

	requireResolvedAlgorithm(t, got, sigalg.Ed25519)

	encOnly := jwks.Ed25519Key(testJWKSKey1, pub)
	encOnly.Use = "enc"

	_, err = jwks.Set{Keys: []jwks.Key{encOnly}}.ResolveExactKeyID(testJWKSKey1)
	if !errors.Is(err, jwks.ErrKeyNotFound) {
		t.Fatalf("use=enc ResolveExactKeyID error = %v, want ErrKeyNotFound", err)
	}

	emptyUse := jwks.Ed25519Key(testJWKSKey1, pub)

	emptyUse.Use = ""
	if _, err := (jwks.Set{Keys: []jwks.Key{emptyUse}}).ResolveExactKeyID(testJWKSKey1); err != nil {
		t.Fatalf("empty use ResolveExactKeyID: %v", err)
	}
}

func TestResolveExactKeyID_ECP256AndRSA(t *testing.T) {
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	x := base64.RawURLEncoding.EncodeToString(tscrypto.PadCoord(ecPriv.X.Bytes(), 32))
	y := base64.RawURLEncoding.EncodeToString(tscrypto.PadCoord(ecPriv.Y.Bytes(), 32))
	ecSet := jwks.Set{Keys: []jwks.Key{{
		Kty: "EC", Kid: "example.com#ec1", Use: "sig", Alg: "ES256", Crv: "P-256", X: x, Y: y,
	}}}

	got, err := ecSet.ResolveExactKeyID("example.com#ec1")
	if err != nil {
		t.Fatalf("EC ResolveExactKeyID: %v", err)
	}

	requireResolvedAlgorithm(t, got, sigalg.ECDSAP256SHA256)

	if _, ok := got.PublicKey.(*ecdsa.PublicKey); !ok {
		t.Fatalf("EC PublicKey type %T", got.PublicKey)
	}

	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	n := base64.RawURLEncoding.EncodeToString(rsaPriv.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsaPriv.E)).Bytes())
	rsaSet := jwks.Set{Keys: []jwks.Key{{
		Kty: "RSA", Kid: "example.com#rsa1", Use: "sig", Alg: "RS256", N: n, E: e,
	}}}

	got, err = rsaSet.ResolveExactKeyID("example.com#rsa1")
	if err != nil {
		t.Fatalf("RSA ResolveExactKeyID: %v", err)
	}

	requireResolvedAlgorithm(t, got, sigalg.RSAPKCS1SHA256)
}

// requireResolvedAlgorithm derives the RFC 9421 native algorithm from the
// resolved key's JWK fields and asserts it matches want.
func requireResolvedAlgorithm(t *testing.T, got sigalg.ResolvedPublicKey, want string) {
	t.Helper()

	alg, err := sigalg.ResolveAlgorithm("", got.JWKKty, got.JWKCrv, got.JWKAlg)
	if err != nil {
		t.Fatalf("ResolveAlgorithm: %v", err)
	}

	if alg != want {
		t.Fatalf("resolved algorithm = %q, want %q", alg, want)
	}
}
