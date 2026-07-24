package jwks_test

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/jwks"
)

const (
	testJWKSKey1 = "example.com#key1"
	testJWKSKey2 = "example.com#key2"
)

func mustEd25519KeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func mustTwoEd25519PublicKeys(t *testing.T) (ed25519.PublicKey, ed25519.PublicKey) {
	t.Helper()
	key1, _ := mustEd25519KeyPair(t)
	key2, _ := mustEd25519KeyPair(t)
	return key1, key2
}

func mustSchemeAuthority(t *testing.T, baseURL string) (scheme, authority string) {
	t.Helper()
	scheme, authority, err := jwks.AuthorityFromBaseURL(baseURL)
	if err != nil {
		t.Fatal(err)
	}
	return scheme, authority
}

func jwksJSONHandler(set jwks.Set) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	}
}

func jwksJSONHandlerWithBefore(set jwks.Set, before func()) http.HandlerFunc {
	base := jwksJSONHandler(set)
	return func(w http.ResponseWriter, r *http.Request) {
		if before != nil {
			before()
		}
		base(w, r)
	}
}

func twoKeyRotationHandler(version *atomic.Int32, key1Pub, key2Pub ed25519.PublicKey) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if version.Load() == 0 {
			_ = json.NewEncoder(w).Encode(jwks.SetFromEd25519PublicKey(testJWKSKey1, key1Pub))
			return
		}
		_ = json.NewEncoder(w).Encode(jwks.SetFromEd25519PublicKey(testJWKSKey2, key2Pub))
	}
}
