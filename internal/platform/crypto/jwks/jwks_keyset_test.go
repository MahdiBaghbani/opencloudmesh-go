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

func TestSetFromEd25519PublicKey_Find(t *testing.T) {
	pub, _ := mustEd25519KeyPair(t)

	set := jwks.SetFromEd25519PublicKey(testJWKSKey1, pub)

	got, err := set.Find(testJWKSKey1)
	if err != nil {
		t.Fatalf("Find: %v", err)
	}

	if got.Algorithm != sigalg.Ed25519 {
		t.Fatalf("Algorithm = %q", got.Algorithm)
	}

	gotPub, ok := got.PublicKey.(ed25519.PublicKey)
	if !ok {
		t.Fatal("expected ed25519 public key")
	}

	if !pub.Equal(gotPub) {
		t.Fatal("public key mismatch")
	}
}

func TestFind_MissingKid(t *testing.T) {
	pub, _ := mustEd25519KeyPair(t)
	set := jwks.SetFromEd25519PublicKey(testJWKSKey1, pub)

	_, err := set.Find("example.com#missing")
	if !errors.Is(err, jwks.ErrKeyNotFound) {
		t.Fatalf("Find() error = %v, want ErrKeyNotFound", err)
	}
}

func TestFind_AmbiguousKid(t *testing.T) {
	pub, _ := mustEd25519KeyPair(t)
	set := jwks.Set{Keys: []jwks.Key{
		jwks.Ed25519Key(testJWKSKey1, pub),
		jwks.Ed25519Key(testJWKSKey1, pub),
	}}

	_, err := set.Find(testJWKSKey1)
	if !errors.Is(err, jwks.ErrAmbiguousKid) {
		t.Fatalf("Find() error = %v, want ErrAmbiguousKid", err)
	}
}

func TestFind_UseSigAndEnc(t *testing.T) {
	pub, _ := mustEd25519KeyPair(t)

	sigKey := jwks.Ed25519Key(testJWKSKey1, pub)
	if sigKey.Use != "sig" {
		t.Fatalf("Ed25519Key Use = %q, want sig", sigKey.Use)
	}

	got, err := jwks.Set{Keys: []jwks.Key{sigKey}}.Find(testJWKSKey1)
	if err != nil {
		t.Fatalf("use=sig Find: %v", err)
	}

	if got.Algorithm != sigalg.Ed25519 {
		t.Fatalf("Algorithm = %q", got.Algorithm)
	}

	encOnly := jwks.Ed25519Key(testJWKSKey1, pub)
	encOnly.Use = "enc"

	_, err = jwks.Set{Keys: []jwks.Key{encOnly}}.Find(testJWKSKey1)
	if !errors.Is(err, jwks.ErrKeyNotFound) {
		t.Fatalf("use=enc Find error = %v, want ErrKeyNotFound", err)
	}

	emptyUse := jwks.Ed25519Key(testJWKSKey1, pub)

	emptyUse.Use = ""
	if _, err := (jwks.Set{Keys: []jwks.Key{emptyUse}}).Find(testJWKSKey1); err != nil {
		t.Fatalf("empty use Find: %v", err)
	}
}

func TestFind_ECP256AndRSA(t *testing.T) {
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	x := base64.RawURLEncoding.EncodeToString(tscrypto.PadCoord(ecPriv.X.Bytes(), 32))
	y := base64.RawURLEncoding.EncodeToString(tscrypto.PadCoord(ecPriv.Y.Bytes(), 32))
	ecSet := jwks.Set{Keys: []jwks.Key{{
		Kty: "EC", Kid: "example.com#ec1", Use: "sig", Alg: "ES256", Crv: "P-256", X: x, Y: y,
	}}}

	got, err := ecSet.Find("example.com#ec1")
	if err != nil {
		t.Fatalf("EC Find: %v", err)
	}

	if got.Algorithm != sigalg.ECDSAP256SHA256 {
		t.Fatalf("EC Algorithm = %q", got.Algorithm)
	}

	if _, ok := got.PublicKey.(*ecdsa.PublicKey); !ok {
		t.Fatalf("EC PublicKey type %T", got.PublicKey)
	}

	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	n := base64.RawURLEncoding.EncodeToString(rsaPriv.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsaPriv.E)).Bytes())
	rsaNoAlg := jwks.Set{Keys: []jwks.Key{{
		Kty: "RSA", Kid: "example.com#rsa1", Use: "sig", N: n, E: e,
	}}}

	got, err = rsaNoAlg.Find("example.com#rsa1")
	if err != nil {
		t.Fatalf("RSA Find: %v", err)
	}

	if got.Algorithm != "" {
		t.Fatalf("RSA without alg Algorithm = %q, want empty", got.Algorithm)
	}
}
