// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package jwks_test

import (
	"crypto/ed25519"
	"net/http"
	"sync/atomic"
	"testing"

	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"

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

func jwksJSONHandler(set jwks.Set) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		tshttp.WriteJSON(w, set)
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
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if version.Load() == 0 {
			tshttp.WriteJSON(w, jwks.SetFromEd25519PublicKey(testJWKSKey1, key1Pub))
			return
		}

		tshttp.WriteJSON(w, jwks.SetFromEd25519PublicKey(testJWKSKey2, key2Pub))
	}
}
