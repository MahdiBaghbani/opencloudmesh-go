// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package crypto_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/jwks"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/keyid"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigalg"
)

func TestVerifyRequest_MissingHeaderAlgUsesJWK(t *testing.T) {
	km := mustHTTPSigKeyManager(t)
	opts := crypto.DefaultRFC9421Options()
	verifier := crypto.NewRFC9421VerifierWithOptions(opts)

	body := []byte(`{"ok":true}`)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "https://example.com/ocm/shares", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Date", opts.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT"))

	digest := base64.StdEncoding.EncodeToString(sigalg.SumSHA256(body))
	req.Header.Set("Content-Digest", "sha-256=:"+digest+":")
	req.Header.Set("Content-Length", strconv.Itoa(len(body)))

	components := httpsigAppendixBComponents
	created := opts.Now().Unix()
	// Signature-Input omits alg; algorithm comes from the JWK. SignRequest
	// always emits alg, so build params and signature base explicitly.
	sigInput := fmt.Sprintf(
		`ocm=("@method" "@target-uri" "content-digest" "content-length");created=%d;keyid=%q;tag="ocm"`,
		created, km.GetKeyID(),
	)
	paramsRaw := strings.TrimPrefix(sigInput, "ocm=")

	sigBase, err := crypto.BuildSignatureBase(req, components)
	if err != nil {
		t.Fatal(err)
	}

	fullBase := sigBase + `"@signature-params": ` + paramsRaw

	sig, err := km.Sign([]byte(fullBase))
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Signature-Input", sigInput)
	req.Header.Set("Signature", fmt.Sprintf("ocm=:%s:", base64.StdEncoding.EncodeToString(sig)))

	result := verifier.VerifyRequest(req, body, httpsigEd25519KeyFetcher(km))
	if !result.Verified {
		t.Fatalf("expected omit-alg verify OK, got %v", result.Error)
	}
}

func TestVerifyRequest_OmitAlgECDSAP256(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	opts := crypto.DefaultRFC9421Options()
	verifier := crypto.NewRFC9421VerifierWithOptions(opts)

	body := []byte(`{"ok":true}`)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "https://example.com/ocm/shares", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Date", opts.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT"))

	digest := base64.StdEncoding.EncodeToString(sigalg.SumSHA256(body))
	req.Header.Set("Content-Digest", "sha-256=:"+digest+":")
	req.Header.Set("Content-Length", strconv.Itoa(len(body)))

	keyID := "example.com#ec1"
	components := httpsigAppendixBComponents
	created := opts.Now().Unix()
	sigInput := fmt.Sprintf(
		`ocm=("@method" "@target-uri" "content-digest" "content-length");created=%d;keyid=%q;tag="ocm"`,
		created, keyID,
	)
	paramsRaw := strings.TrimPrefix(sigInput, "ocm=")

	sigBase, err := crypto.BuildSignatureBase(req, components)
	if err != nil {
		t.Fatal(err)
	}

	fullBase := sigBase + `"@signature-params": ` + paramsRaw
	sum := sha256.Sum256([]byte(fullBase))

	r, s, err := ecdsa.Sign(rand.Reader, priv, sum[:])
	if err != nil {
		t.Fatal(err)
	}

	raw, err := sigalg.EncodeECDSARawRS(r, s, 32)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Signature-Input", sigInput)
	req.Header.Set("Signature", fmt.Sprintf("ocm=:%s:", base64.StdEncoding.EncodeToString(raw)))

	result := verifier.VerifyRequest(req, body, func(id string) (sigalg.ResolvedPublicKey, error) {
		return sigalg.ResolvedPublicKey{
			KeyID: id, PublicKey: &priv.PublicKey,
			JWKKty: "EC", JWKCrv: "P-256", JWKAlg: "ES256",
		}, nil
	})
	if !result.Verified {
		t.Fatalf("expected omit-alg ECDSA verify OK, got %v", result.Error)
	}
}

func TestResolveExactKeyID_ExactMatchResolvesKey(t *testing.T) {
	km := mustHTTPSigKeyManager(t)
	set := km.JWKS()

	got, err := set.ResolveExactKeyID(km.GetKeyID())
	if err != nil {
		t.Fatalf("ResolveExactKeyID: %v", err)
	}

	if got.KeyID != km.GetKeyID() {
		t.Fatalf("KeyID = %q, want %q", got.KeyID, km.GetKeyID())
	}

	alg, err := sigalg.ResolveAlgorithm("", got.JWKKty, got.JWKCrv, got.JWKAlg)
	if err != nil {
		t.Fatalf("ResolveAlgorithm: %v", err)
	}

	if alg != sigalg.Ed25519 {
		t.Fatalf("resolved algorithm = %q, want %q", alg, sigalg.Ed25519)
	}

	pub, ok := got.PublicKey.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("PublicKey type %T, want ed25519.PublicKey", got.PublicKey)
	}

	if !pub.Equal(km.GetSigningKey().PublicKey) {
		t.Fatal("resolved public key mismatch")
	}
}

func TestResolveExactKeyID_RejectsNonExactKeyID(t *testing.T) {
	km := mustHTTPSigKeyManager(t)
	set := km.JWKS() // sole kid: example.com#key1

	nonExact := []struct {
		name  string
		keyID string
	}{
		{"default-port authority variant", "example.com:443#key1"},
		{"case variant", "Example.com#key1"},
		{"absolute URI form", "https://example.com#key1"},
		{"fragment prefix", "example.com#key"},
		{"fragment suffix", "example.com#key10"},
		{"different authority", "other.example#key1"},
		{"empty keyid", ""},
	}

	for _, tt := range nonExact {
		t.Run(tt.name, func(t *testing.T) {
			_, err := set.ResolveExactKeyID(tt.keyID)
			if !errors.Is(err, jwks.ErrKeyNotFound) {
				t.Fatalf("ResolveExactKeyID(%q) error = %v, want ErrKeyNotFound", tt.keyID, err)
			}
		})
	}
}

func TestResolveExactKeyID_RejectsAmbiguousExactKid(t *testing.T) {
	km := mustHTTPSigKeyManager(t)
	key := jwks.Ed25519Key(km.GetKeyID(), km.GetSigningKey().PublicKey)
	set := jwks.Set{Keys: []jwks.Key{key, key}}

	_, err := set.ResolveExactKeyID(km.GetKeyID())
	if !errors.Is(err, jwks.ErrAmbiguousKid) {
		t.Fatalf("ResolveExactKeyID error = %v, want ErrAmbiguousKid", err)
	}
}

func TestKidEqualsExact(t *testing.T) {
	// The verifier's exact resolver requires byte-for-byte equality; no
	// authority normalization or case folding.
	if keyid.KidEqualsExact("example.com:443#key1", "example.com#key1") {
		t.Fatal("KidEqualsExact must reject non-equal authority forms")
	}

	if !keyid.KidEqualsExact("example.com#key1", "example.com#key1") {
		t.Fatal("KidEqualsExact must accept identical strings")
	}
}

func TestVerifyRequest_ExactKeyIDResolutionEndToEnd(t *testing.T) {
	km := mustHTTPSigKeyManager(t)
	opts := httpsigFixedOptions()
	signer := crypto.NewRFC9421SignerWithOptions(km, opts)
	verifier := crypto.NewRFC9421VerifierWithOptions(opts)

	body := httpsigTestBodyJSON

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://example.com/ocm/shares", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}

	req.Host = "example.com"
	req.Header.Set("Content-Type", "application/json")

	if err := signer.SignRequest(req, body); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}

	result := verifier.VerifyRequest(req, body, func(keyID string) (sigalg.ResolvedPublicKey, error) {
		return km.JWKS().ResolveExactKeyID(keyID)
	})
	if !result.Verified {
		t.Fatalf("expected exact keyid resolution to verify: %v", result.Error)
	}

	if result.KeyID != km.GetKeyID() {
		t.Fatalf("KeyID = %q, want %q", result.KeyID, km.GetKeyID())
	}
}

func TestVerifyRequest_RejectsKeyIDWithoutExactKid(t *testing.T) {
	km := mustHTTPSigKeyManager(t)
	opts := httpsigFixedOptions()
	signer := crypto.NewRFC9421SignerWithOptions(km, opts)
	verifier := crypto.NewRFC9421VerifierWithOptions(opts)

	body := httpsigTestBodyJSON

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://example.com/ocm/shares", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}

	req.Host = "example.com"
	req.Header.Set("Content-Type", "application/json")

	if err := signer.SignRequest(req, body); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}

	// The peer JWKS holds the same key material under a canonically
	// equivalent but not byte-equal kid; exact matching must miss it.
	peerSet := jwks.SetFromEd25519PublicKey("example.com:443#key1", km.GetSigningKey().PublicKey)

	result := verifier.VerifyRequest(req, body, peerSet.ResolveExactKeyID)
	if result.Verified {
		t.Fatal("expected rejection when no JWKS kid exactly equals keyid")
	}

	if result.Reason != crypto.ReasonKeyNotFound {
		t.Fatalf("Reason = %q, want %q (err=%v)", result.Reason, crypto.ReasonKeyNotFound, result.Error)
	}

	if !errors.Is(result.Error, jwks.ErrKeyNotFound) {
		t.Fatalf("error = %v, want wrapped ErrKeyNotFound", result.Error)
	}
}

func TestVerifyRequest_KeyNotFoundVsLookupFailed(t *testing.T) {
	verifier := crypto.NewRFC9421Verifier()
	now := time.Now().Unix()
	body := httpsigTestBodyJSON
	digest := httpsigContentDigestHeader(body)

	newReq := func() *http.Request {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "https://example.com/ocm/shares", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Content-Digest", digest)
		req.Header.Set("Content-Length", strconv.Itoa(len(body)))
		req.Header.Set("Date", httpsigStandardDate)
		req.Header.Set("Signature-Input", fmt.Sprintf(
			`ocm=("@method" "@target-uri" "content-digest" "content-length" "date");created=%d;keyid="example.com#key1";alg="ed25519";tag="ocm"`,
			now,
		))
		req.Header.Set("Signature", httpsigPlaceholderSig)

		return req
	}

	t.Run("key_not_found", func(t *testing.T) {
		result := verifier.VerifyRequest(newReq(), body, func(string) (sigalg.ResolvedPublicKey, error) {
			return sigalg.ResolvedPublicKey{}, fmt.Errorf("jwks lookup: %w", jwks.ErrKeyNotFound)
		})
		if result.Verified {
			t.Fatal("expected failure")
		}

		if result.Reason != crypto.ReasonKeyNotFound {
			t.Fatalf("Reason=%q want key_not_found (err=%v)", result.Reason, result.Error)
		}
	})

	t.Run("key_lookup_failed", func(t *testing.T) {
		result := verifier.VerifyRequest(newReq(), body, func(string) (sigalg.ResolvedPublicKey, error) {
			return sigalg.ResolvedPublicKey{}, errors.New("jwks: fetch failed: connection refused")
		})
		if result.Verified {
			t.Fatal("expected failure")
		}

		if result.Reason != crypto.ReasonKeyLookupFailed {
			t.Fatalf("Reason=%q want key_lookup_failed (err=%v)", result.Reason, result.Error)
		}
	})
}
