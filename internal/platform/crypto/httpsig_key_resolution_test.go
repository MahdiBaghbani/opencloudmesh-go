package crypto_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/jwks"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigalg"
)

func TestVerifyRequest_MissingHeaderAlgUsesJWK(t *testing.T) {
	km := mustHTTPSigKeyManager(t)
	opts := crypto.DefaultRFC9421Options()
	verifier := crypto.NewRFC9421VerifierWithOptions(opts)

	body := []byte(`{"ok":true}`)
	req := httptest.NewRequest(http.MethodPost, "https://example.com/ocm/shares", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Date", opts.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT"))

	digest := base64.StdEncoding.EncodeToString(sigalg.SumSHA256(body))
	req.Header.Set("Content-Digest", "sha-256=:"+digest+":")
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))

	components := httpsigAppendixBComponents
	created := opts.Now().Unix()
	// Signature-Input omits alg; algorithm comes from the JWK. SignRequest
	// always emits alg, so build params and signature base explicitly.
	sigInput := fmt.Sprintf(
		`ocm=("@method" "@target-uri" "content-digest" "content-length" "date");created=%d;keyid=%q;tag="ocm"`,
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
	req := httptest.NewRequest(http.MethodPost, "https://example.com/ocm/shares", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Date", opts.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT"))

	digest := base64.StdEncoding.EncodeToString(sigalg.SumSHA256(body))
	req.Header.Set("Content-Digest", "sha-256=:"+digest+":")
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))

	keyID := "example.com#ec1"
	components := httpsigAppendixBComponents
	created := opts.Now().Unix()
	sigInput := fmt.Sprintf(
		`ocm=("@method" "@target-uri" "content-digest" "content-length" "date");created=%d;keyid=%q;tag="ocm"`,
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
			KeyID: id, Algorithm: sigalg.ECDSAP256SHA256, PublicKey: &priv.PublicKey,
			JWKKty: "EC", JWKCrv: "P-256", JWKAlg: "ES256",
		}, nil
	})
	if !result.Verified {
		t.Fatalf("expected omit-alg ECDSA verify OK, got %v", result.Error)
	}
}

func TestVerifyRequest_KeyNotFoundVsLookupFailed(t *testing.T) {
	verifier := crypto.NewRFC9421Verifier()
	now := time.Now().Unix()
	body := httpsigTestBodyJSON
	digest := httpsigContentDigestHeader(body)

	newReq := func() *http.Request {
		req := httptest.NewRequest(http.MethodPost, "https://example.com/ocm/shares", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Content-Digest", digest)
		req.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
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
			return sigalg.ResolvedPublicKey{}, fmt.Errorf("jwks: fetch failed: connection refused")
		})
		if result.Verified {
			t.Fatal("expected failure")
		}

		if result.Reason != crypto.ReasonKeyLookupFailed {
			t.Fatalf("Reason=%q want key_lookup_failed (err=%v)", result.Reason, result.Error)
		}
	})
}
