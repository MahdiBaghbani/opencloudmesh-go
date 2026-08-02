// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package crypto_test

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigalg"
	tscrypto "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/crypto"
)

const (
	httpsigTestOrigin    = "https://example.com"
	httpsigFixedUnixTime = int64(1_730_815_200)
	httpsigStandardDate  = "Fri, 16 Jan 2026 13:37:00 GMT"
)

var (
	httpsigTestBodyJSON        = []byte(`{"test":"data"}`)
	httpsigAppendixBComponents = []string{
		"@method", "@target-uri", "content-digest", "content-length",
	}
	httpsigPlaceholderSig    = "ocm=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:"
	httpsigPlaceholderSigAlt = "ocm=:AAAA:"
)

func httpsigFixedNow() time.Time {
	return time.Unix(httpsigFixedUnixTime, 0)
}

func mustHTTPSigKeyManager(t testing.TB) *crypto.KeyManager {
	t.Helper()
	return tscrypto.MustTestKeyManager(t, httpsigTestOrigin)
}

func httpsigFixedOptions() crypto.RFC9421Options {
	opts := crypto.DefaultRFC9421Options()
	opts.Now = httpsigFixedNow

	return opts
}

func httpsigEd25519KeyFetcher(km *crypto.KeyManager) func(string) (sigalg.ResolvedPublicKey, error) {
	return func(keyID string) (sigalg.ResolvedPublicKey, error) {
		return sigalg.ResolvedPublicKey{
			KeyID: keyID, PublicKey: km.GetSigningKey().PublicKey,
			JWKKty: "OKP", JWKCrv: "Ed25519", JWKAlg: "Ed25519",
		}, nil
	}
}

func httpsigVerifierWithNow(base crypto.RFC9421Options, now time.Time) *crypto.RFC9421Verifier {
	base.Now = func() time.Time { return now }
	return crypto.NewRFC9421VerifierWithOptions(base)
}

func httpsigContentDigestHeader(body []byte) string {
	return "sha-256=:" + base64.StdEncoding.EncodeToString(sigalg.SumSHA256(body)) + ":"
}
