package crypto_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/jwks"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigalg"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigparams"
)

func TestRFC9421_SignAndVerify_EmptyBody(t *testing.T) {
	km := crypto.NewKeyManager("", "https://example.com")
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatalf("LoadOrGenerate failed: %v", err)
	}

	opts := crypto.DefaultRFC9421Options()
	opts.Now = func() time.Time { return time.Unix(1_730_815_200, 0) }

	signer := crypto.NewRFC9421SignerWithOptions(km, opts)
	verifier := crypto.NewRFC9421VerifierWithOptions(opts)

	req, err := http.NewRequest("GET", "https://example.com/ocm/discovery", nil)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}
	req.Host = "example.com"

	if err := signer.SignRequest(req, nil); err != nil {
		t.Fatalf("SignRequest failed: %v", err)
	}

	sigInput := req.Header.Get("Signature-Input")
	for _, want := range []string{`"@method"`, `"@target-uri"`, `"content-digest"`, `"content-length"`, `"date"`} {
		if !strings.Contains(sigInput, want) {
			t.Fatalf("empty-body Signature-Input missing %s: %q", want, sigInput)
		}
	}
	wantDigest := "sha-256=:" + base64.StdEncoding.EncodeToString(sigalg.SumSHA256(nil)) + ":"
	if got := req.Header.Get("Content-Digest"); got != wantDigest {
		t.Errorf("Content-Digest = %q, want %q", got, wantDigest)
	}
	if got := req.Header.Get("Content-Length"); got != "0" {
		t.Errorf("Content-Length = %q, want 0", got)
	}

	result := verifier.VerifyRequest(req, nil, func(keyID string) (sigalg.ResolvedPublicKey, error) {
		return sigalg.ResolvedPublicKey{
			KeyID: keyID, Algorithm: sigalg.Ed25519, PublicKey: km.GetSigningKey().PublicKey,
			JWKKty: "OKP", JWKCrv: "Ed25519",
		}, nil
	})
	if !result.Verified {
		t.Fatalf("empty-body verification failed: %v", result.Error)
	}
}

func TestRFC9421_SignAndVerify(t *testing.T) {
	km := crypto.NewKeyManager("", "https://example.com")
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatalf("LoadOrGenerate failed: %v", err)
	}

	opts := crypto.DefaultRFC9421Options()
	opts.Now = func() time.Time { return time.Unix(1_730_815_200, 0) }

	signer := crypto.NewRFC9421SignerWithOptions(km, opts)
	verifier := crypto.NewRFC9421VerifierWithOptions(opts)

	body := []byte(`{"test": "data"}`)

	req, err := http.NewRequest("POST", "https://example.com/ocm/shares", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}
	req.Host = "example.com"
	req.Header.Set("Content-Type", "application/json")

	if err := signer.SignRequest(req, body); err != nil {
		t.Fatalf("SignRequest failed: %v", err)
	}

	sigInput := req.Header.Get("Signature-Input")
	if !strings.HasPrefix(sigInput, "ocm=") {
		t.Fatalf("Signature-Input = %q, want ocm= prefix", sigInput)
	}
	if req.Header.Get("Signature") == "" {
		t.Error("missing Signature header")
	}
	if req.Header.Get("Date") == "" {
		t.Error("missing Date header")
	}

	result := verifier.VerifyRequest(req, body, func(keyID string) (sigalg.ResolvedPublicKey, error) {
		return sigalg.ResolvedPublicKey{
			KeyID: keyID, Algorithm: sigalg.Ed25519, PublicKey: km.GetSigningKey().PublicKey,
			JWKKty: "OKP", JWKCrv: "Ed25519",
		}, nil
	})

	if !result.Verified {
		t.Errorf("verification failed: %v", result.Error)
	}
	if result.KeyID != km.GetKeyID() {
		t.Errorf("expected keyId %q, got %q", km.GetKeyID(), result.KeyID)
	}
}

func TestRFC9421_SignatureParams(t *testing.T) {
	km := crypto.NewKeyManager("", "https://example.com")
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatalf("LoadOrGenerate failed: %v", err)
	}

	opts := crypto.DefaultRFC9421Options()
	opts.Now = func() time.Time { return time.Unix(1_730_815_200, 0) }
	signer := crypto.NewRFC9421SignerWithOptions(km, opts)

	body := []byte(`{"test": "data"}`)
	req, _ := http.NewRequest("POST", "https://example.com/ocm/shares", bytes.NewReader(body))
	req.Host = "example.com"
	req.Header.Set("Content-Type", "application/json")

	if err := signer.SignRequest(req, body); err != nil {
		t.Fatalf("SignRequest failed: %v", err)
	}

	sigInput := req.Header.Get("Signature-Input")
	for _, want := range []string{`"@method"`, `"@target-uri"`, `"content-digest"`, `"content-length"`, `"date"`, "created=", "keyid=", `alg="ed25519"`} {
		if !strings.Contains(sigInput, want) {
			t.Errorf("Signature-Input missing %q: %q", want, sigInput)
		}
	}
}

func TestRFC9421_VerifyMissingHeaders(t *testing.T) {
	verifier := crypto.NewRFC9421Verifier()

	req := httptest.NewRequest("POST", "https://example.com/ocm/shares", nil)

	if verifier.HasSignatureHeaders(req) {
		t.Error("should not have signature headers")
	}

	result := verifier.VerifyRequest(req, nil, func(keyID string) (sigalg.ResolvedPublicKey, error) {
		return sigalg.ResolvedPublicKey{}, nil
	})

	if result.Verified {
		t.Error("should not verify without signature headers")
	}
	if result.Error == nil {
		t.Error("should return error for missing headers")
	}
}

func TestRFC9421_VerifyInvalidSignature(t *testing.T) {
	km1 := crypto.NewKeyManager("", "https://example.com")
	km2 := crypto.NewKeyManager("", "https://attacker.com")
	km1.LoadOrGenerate()
	km2.LoadOrGenerate()

	opts := crypto.DefaultRFC9421Options()
	opts.Now = func() time.Time { return time.Unix(1_730_815_200, 0) }

	signer := crypto.NewRFC9421SignerWithOptions(km1, opts)
	verifier := crypto.NewRFC9421VerifierWithOptions(opts)

	body := []byte(`{"test": "data"}`)
	req, _ := http.NewRequest("POST", "https://example.com/ocm/shares", bytes.NewReader(body))
	req.Host = "example.com"
	req.Header.Set("Content-Type", "application/json")

	signer.SignRequest(req, body)

	result := verifier.VerifyRequest(req, body, func(keyID string) (sigalg.ResolvedPublicKey, error) {
		return sigalg.ResolvedPublicKey{
			KeyID: keyID, Algorithm: sigalg.Ed25519, PublicKey: km2.GetSigningKey().PublicKey,
			JWKKty: "OKP", JWKCrv: "Ed25519",
		}, nil
	})

	if result.Verified {
		t.Error("verification should fail with wrong key")
	}
}

func TestRFC9421_VerifyRejectsStaleCreated(t *testing.T) {
	km := crypto.NewKeyManager("", "https://example.com")
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatal(err)
	}

	now := time.Unix(1_730_815_200, 0)
	opts := crypto.DefaultRFC9421Options()
	opts.Now = func() time.Time { return now }
	opts.CreatedMaxAge = time.Minute

	signer := crypto.NewRFC9421SignerWithOptions(km, opts)

	body := []byte(`{"test": "data"}`)
	req, _ := http.NewRequest("POST", "https://example.com/ocm/shares", bytes.NewReader(body))
	req.Host = "example.com"

	if err := signer.SignRequest(req, body); err != nil {
		t.Fatal(err)
	}

	staleVerifier := crypto.NewRFC9421VerifierWithOptions(crypto.RFC9421Options{
		Label:              opts.Label,
		CreatedMaxAge:      opts.CreatedMaxAge,
		CreatedMaxSkew:     opts.CreatedMaxSkew,
		AllowedAlgorithms:  opts.AllowedAlgorithms,
		RequiredComponents: opts.RequiredComponents,
		Now:                func() time.Time { return now.Add(2 * time.Minute) },
	})

	result := staleVerifier.VerifyRequest(req, body, func(keyID string) (sigalg.ResolvedPublicKey, error) {
		return sigalg.ResolvedPublicKey{
			KeyID: keyID, Algorithm: sigalg.Ed25519, PublicKey: km.GetSigningKey().PublicKey,
			JWKKty: "OKP", JWKCrv: "Ed25519",
		}, nil
	})
	if result.Verified {
		t.Fatal("expected stale created to fail verification")
	}
	if result.Reason != crypto.ReasonStaleCreated {
		t.Fatalf("Reason = %q, want %q", result.Reason, crypto.ReasonStaleCreated)
	}
	if result.Error == nil || !strings.Contains(result.Error.Error(), "stale") {
		t.Fatalf("error = %v, want stale created", result.Error)
	}
}

func TestRFC9421_VerifyRejectsFutureCreated(t *testing.T) {
	km := crypto.NewKeyManager("", "https://example.com")
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatal(err)
	}

	signTime := time.Unix(1_730_815_200, 0)
	verifyTime := signTime.Add(-2 * time.Minute)

	opts := crypto.DefaultRFC9421Options()
	opts.Now = func() time.Time { return signTime }
	opts.CreatedMaxSkew = time.Minute

	signer := crypto.NewRFC9421SignerWithOptions(km, opts)

	body := []byte(`{"test": "data"}`)
	req, err := http.NewRequest("POST", "https://example.com/ocm/shares", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "example.com"

	if err := signer.SignRequest(req, body); err != nil {
		t.Fatal(err)
	}

	futureVerifier := crypto.NewRFC9421VerifierWithOptions(crypto.RFC9421Options{
		Label:              opts.Label,
		CreatedMaxAge:      opts.CreatedMaxAge,
		CreatedMaxSkew:     opts.CreatedMaxSkew,
		AllowedAlgorithms:  opts.AllowedAlgorithms,
		RequiredComponents: opts.RequiredComponents,
		Now:                func() time.Time { return verifyTime },
	})

	result := futureVerifier.VerifyRequest(req, body, func(keyID string) (sigalg.ResolvedPublicKey, error) {
		return sigalg.ResolvedPublicKey{
			KeyID: keyID, Algorithm: sigalg.Ed25519, PublicKey: km.GetSigningKey().PublicKey,
			JWKKty: "OKP", JWKCrv: "Ed25519",
		}, nil
	})
	if result.Verified {
		t.Fatal("expected future created to fail verification")
	}
	if result.Reason != crypto.ReasonFutureCreated {
		t.Fatalf("Reason = %q, want %q", result.Reason, crypto.ReasonFutureCreated)
	}
	if result.Error == nil || !strings.Contains(result.Error.Error(), "too far in the future") {
		t.Fatalf("error = %v, want future created rejection", result.Error)
	}
}

func TestRFC9421_VerifyRejectsHMAC(t *testing.T) {
	verifier := crypto.NewRFC9421Verifier()
	now := time.Now().Unix()
	req := httptest.NewRequest("POST", "https://example.com/test", nil)
	req.Header.Set("Date", "Fri, 16 Jan 2026 13:37:00 GMT")
	emptyDigest := base64.StdEncoding.EncodeToString(sigalg.SumSHA256(nil))
	req.Header.Set("Content-Digest", "sha-256=:"+emptyDigest+":")
	req.Header.Set("Content-Length", "0")
	req.Header.Set("Signature-Input", fmt.Sprintf(
		`ocm=("@method" "@target-uri" "content-digest" "content-length" "date");created=%d;keyid="example.com#key1";alg="hmac-sha256";tag="ocm"`,
		now,
	))
	req.Header.Set("Signature", "ocm=:AAAA:")

	fetches := 0
	result := verifier.VerifyRequest(req, nil, func(keyID string) (sigalg.ResolvedPublicKey, error) {
		fetches++
		return sigalg.ResolvedPublicKey{
			KeyID: keyID, Algorithm: sigalg.Ed25519,
			JWKKty: "OKP", JWKCrv: "Ed25519",
		}, nil
	})
	if result.Verified {
		t.Fatal("expected symmetric algorithm rejection")
	}
	if result.Reason != crypto.ReasonAlgorithmRejected {
		t.Fatalf("Reason = %q, want %q (err=%v)", result.Reason, crypto.ReasonAlgorithmRejected, result.Error)
	}
	if fetches != 1 {
		t.Fatalf("fetches = %d, want 1 after created/components", fetches)
	}
}

func TestContentDigest(t *testing.T) {
	body := []byte(`{"test": "data"}`)

	req := httptest.NewRequest("POST", "/test", bytes.NewReader(body))

	if err := crypto.VerifyContentDigest(req, body); err != nil {
		t.Errorf("should pass without Content-Digest: %v", err)
	}

	km := crypto.NewKeyManager("", "https://example.com")
	km.LoadOrGenerate()
	opts := crypto.DefaultRFC9421Options()
	opts.Now = func() time.Time { return time.Unix(1_730_815_200, 0) }
	signer := crypto.NewRFC9421SignerWithOptions(km, opts)

	req2, _ := http.NewRequest("POST", "https://example.com/test", bytes.NewReader(body))
	req2.Host = "example.com"
	signer.SignRequest(req2, body)

	if err := crypto.VerifyContentDigest(req2, body); err != nil {
		t.Errorf("verification should pass with correct body: %v", err)
	}

	wrongBody := []byte(`{"wrong": "body"}`)
	if err := crypto.VerifyContentDigest(req2, wrongBody); err == nil {
		t.Error("verification should fail with wrong body")
	}
}

func TestVerifyContentDigest_MultiDigest(t *testing.T) {
	body := []byte(`{"test":"data"}`)
	sha256Val := base64.StdEncoding.EncodeToString(sigalg.SumSHA256(body))
	sha512Val := base64.StdEncoding.EncodeToString(sigalg.SumSHA512(body))

	req := httptest.NewRequest("POST", "/test", bytes.NewReader(body))
	req.Header.Set("Content-Digest", fmt.Sprintf("sha-256=:%s:, sha-512=:%s:", sha256Val, sha512Val))

	if err := crypto.VerifyContentDigest(req, body); err != nil {
		t.Fatalf("multi-digest verify failed: %v", err)
	}
}

func TestVerifyContentDigest_MultiDigest_OneTampered(t *testing.T) {
	body := []byte(`{"test":"data"}`)
	sha256Val := base64.StdEncoding.EncodeToString(sigalg.SumSHA256(body))
	tampered := base64.StdEncoding.EncodeToString(sigalg.SumSHA512([]byte("wrong")))

	req := httptest.NewRequest("POST", "/test", bytes.NewReader(body))
	req.Header.Set("Content-Digest", fmt.Sprintf("sha-256=:%s:, sha-512=:%s:", sha256Val, tampered))

	if err := crypto.VerifyContentDigest(req, body); err == nil {
		t.Fatal("expected failure when one recognized digest is tampered")
	}
}

func TestVerifyContentDigest_UnknownPlusRecognizedRejected(t *testing.T) {
	body := []byte(`{"test":"data"}`)
	sha256Val := base64.StdEncoding.EncodeToString(sigalg.SumSHA256(body))

	req := httptest.NewRequest("POST", "/test", bytes.NewReader(body))
	req.Header.Set("Content-Digest", fmt.Sprintf("sha-256=:%s:, foo=:%s:", sha256Val, sha256Val))

	if err := crypto.VerifyContentDigest(req, body); err == nil {
		t.Fatal("expected rejection when an unrecognized digest algorithm is listed")
	}
}

func TestVerifyContentDigest_OnlyUnknownAlgorithmsRejected(t *testing.T) {
	body := []byte(`{"test":"data"}`)
	val := base64.StdEncoding.EncodeToString(sigalg.SumSHA256(body))

	req := httptest.NewRequest("POST", "/test", bytes.NewReader(body))
	req.Header.Set("Content-Digest", fmt.Sprintf("foo=:%s:, bar=:%s:", val, val))

	if err := crypto.VerifyContentDigest(req, body); err == nil {
		t.Fatal("expected rejection when no recognized digest is present")
	}
}

func TestRequiredComponentsForRequest(t *testing.T) {
	req := httptest.NewRequest("GET", "https://example.com/ocm/discovery", nil)
	req.Header.Set("Date", "Fri, 16 Jan 2026 13:37:00 GMT")

	want := []string{"@method", "@target-uri", "content-digest", "content-length", "date"}
	empty := crypto.RequiredComponentsForRequest(req, nil)
	if len(empty) != len(want) {
		t.Fatalf("empty body components = %v, want %v", empty, want)
	}
	for i, c := range want {
		if empty[i] != c {
			t.Fatalf("empty[%d] = %q, want %q", i, empty[i], c)
		}
	}

	body := []byte(`{"x":1}`)
	withBody := crypto.RequiredComponentsForRequest(req, body)
	if len(withBody) != len(want) {
		t.Fatalf("body components = %v, want %v", withBody, want)
	}
	for i, c := range want {
		if withBody[i] != c {
			t.Fatalf("body[%d] = %q, want %q", i, withBody[i], c)
		}
	}
}

func TestVerifyRequest_RejectsMissingContentDigestHeaderOnNonEmptyBody(t *testing.T) {
	km := crypto.NewKeyManager("", "https://example.com")
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatal(err)
	}
	opts := crypto.DefaultRFC9421Options()
	opts.Now = func() time.Time { return time.Unix(1_730_815_200, 0) }
	signer := crypto.NewRFC9421SignerWithOptions(km, opts)
	verifier := crypto.NewRFC9421VerifierWithOptions(opts)

	body := []byte(`{"test":"data"}`)
	req, _ := http.NewRequest("POST", "https://example.com/ocm/shares", bytes.NewReader(body))
	req.Host = "example.com"
	if err := signer.SignRequest(req, body); err != nil {
		t.Fatal(err)
	}
	req.Header.Del("Content-Digest")

	fetched := false
	result := verifier.VerifyRequest(req, body, func(string) (sigalg.ResolvedPublicKey, error) {
		fetched = true
		return sigalg.ResolvedPublicKey{}, fmt.Errorf("should not fetch")
	})
	if result.Verified {
		t.Fatal("expected missing Content-Digest rejection")
	}
	if result.Reason != crypto.ReasonContentDigest {
		t.Fatalf("Reason=%q want content_digest (err=%v)", result.Reason, result.Error)
	}
	if fetched {
		t.Fatal("key fetch must not run after missing Content-Digest rejection")
	}
}

func TestVerifyRequest_RejectsMissingContentLengthHeaderOnNonEmptyBody(t *testing.T) {
	km := crypto.NewKeyManager("", "https://example.com")
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatal(err)
	}
	opts := crypto.DefaultRFC9421Options()
	opts.Now = func() time.Time { return time.Unix(1_730_815_200, 0) }
	signer := crypto.NewRFC9421SignerWithOptions(km, opts)
	verifier := crypto.NewRFC9421VerifierWithOptions(opts)

	body := []byte(`{"test":"data"}`)
	req, _ := http.NewRequest("POST", "https://example.com/ocm/shares", bytes.NewReader(body))
	req.Host = "example.com"
	if err := signer.SignRequest(req, body); err != nil {
		t.Fatal(err)
	}
	req.Header.Del("Content-Length")

	fetched := false
	result := verifier.VerifyRequest(req, body, func(string) (sigalg.ResolvedPublicKey, error) {
		fetched = true
		return sigalg.ResolvedPublicKey{}, fmt.Errorf("should not fetch")
	})
	if result.Verified {
		t.Fatal("expected missing Content-Length rejection")
	}
	if result.Reason != crypto.ReasonContentDigest {
		t.Fatalf("Reason=%q want content_digest (err=%v)", result.Reason, result.Error)
	}
	if fetched {
		t.Fatal("key fetch must not run after missing Content-Length rejection")
	}
}

func TestVerifyRequest_RejectsMissingDigestComponentsOnNonEmptyBody(t *testing.T) {
	verifier := crypto.NewRFC9421Verifier()
	now := time.Now().Unix()
	body := []byte(`{"test":"data"}`)

	req := httptest.NewRequest("POST", "https://example.com/ocm/shares", bytes.NewReader(body))
	req.Header.Set("Date", "Fri, 16 Jan 2026 13:37:00 GMT")
	req.Header.Set("Signature-Input", fmt.Sprintf(
		`ocm=("@method" "@target-uri" "date");created=%d;keyid="example.com#key1";alg="ed25519";tag="ocm"`,
		now,
	))
	req.Header.Set("Signature", "ocm=:AAAA:")

	result := verifier.VerifyRequest(req, body, func(string) (sigalg.ResolvedPublicKey, error) {
		return sigalg.ResolvedPublicKey{}, fmt.Errorf("should not fetch")
	})
	if result.Verified {
		t.Fatal("expected missing component rejection")
	}
	if result.Reason != crypto.ReasonMissingComponent {
		t.Fatalf("Reason=%q want missing_component", result.Reason)
	}
}

func TestVerifyRequest_RejectsContentDigestMismatch(t *testing.T) {
	km := crypto.NewKeyManager("", "https://example.com")
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatal(err)
	}
	opts := crypto.DefaultRFC9421Options()
	opts.Now = func() time.Time { return time.Unix(1_730_815_200, 0) }
	signer := crypto.NewRFC9421SignerWithOptions(km, opts)
	verifier := crypto.NewRFC9421VerifierWithOptions(opts)

	body := []byte(`{"test":"data"}`)
	req, _ := http.NewRequest("POST", "https://example.com/ocm/shares", bytes.NewReader(body))
	req.Host = "example.com"
	if err := signer.SignRequest(req, body); err != nil {
		t.Fatal(err)
	}

	tampered := []byte(`{"test":"xoxo"}`)
	if len(tampered) != len(body) {
		t.Fatalf("tampered len = %d, want %d", len(tampered), len(body))
	}
	if bytes.Equal(sigalg.SumSHA256(body), sigalg.SumSHA256(tampered)) {
		t.Fatal("tampered body must produce a different digest")
	}
	result := verifier.VerifyRequest(req, tampered, func(keyID string) (sigalg.ResolvedPublicKey, error) {
		return sigalg.ResolvedPublicKey{
			KeyID: keyID, Algorithm: sigalg.Ed25519, PublicKey: km.GetSigningKey().PublicKey,
			JWKKty: "OKP", JWKCrv: "Ed25519",
		}, nil
	})
	if result.Verified {
		t.Fatal("expected digest mismatch rejection")
	}
	if result.Reason != crypto.ReasonContentDigest {
		t.Fatalf("Reason=%q want content_digest", result.Reason)
	}
}

func TestRFC9421_VerifyCreatedBoundaryAtMaxSkew(t *testing.T) {
	km := crypto.NewKeyManager("", "https://example.com")
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatal(err)
	}

	signTime := time.Unix(1_730_815_200, 0)
	maxSkew := 60 * time.Second
	opts := crypto.DefaultRFC9421Options()
	opts.Now = func() time.Time { return signTime }
	opts.CreatedMaxSkew = maxSkew

	signer := crypto.NewRFC9421SignerWithOptions(km, opts)
	body := []byte(`{"test":"data"}`)
	req, _ := http.NewRequest("POST", "https://example.com/ocm/shares", bytes.NewReader(body))
	req.Host = "example.com"
	if err := signer.SignRequest(req, body); err != nil {
		t.Fatal(err)
	}

	atSkewVerifier := crypto.NewRFC9421VerifierWithOptions(crypto.RFC9421Options{
		Label:              opts.Label,
		CreatedMaxAge:      opts.CreatedMaxAge,
		CreatedMaxSkew:     maxSkew,
		AllowedAlgorithms:  opts.AllowedAlgorithms,
		RequiredComponents: opts.RequiredComponents,
		Now:                func() time.Time { return signTime.Add(-maxSkew) },
	})
	result := atSkewVerifier.VerifyRequest(req, body, func(keyID string) (sigalg.ResolvedPublicKey, error) {
		return sigalg.ResolvedPublicKey{
			KeyID: keyID, Algorithm: sigalg.Ed25519, PublicKey: km.GetSigningKey().PublicKey,
			JWKKty: "OKP", JWKCrv: "Ed25519",
		}, nil
	})
	if !result.Verified {
		t.Fatalf("created at max skew should verify: %v", result.Error)
	}

	pastSkewVerifier := crypto.NewRFC9421VerifierWithOptions(crypto.RFC9421Options{
		Label:              opts.Label,
		CreatedMaxAge:      opts.CreatedMaxAge,
		CreatedMaxSkew:     maxSkew,
		AllowedAlgorithms:  opts.AllowedAlgorithms,
		RequiredComponents: opts.RequiredComponents,
		Now:                func() time.Time { return signTime.Add(-maxSkew - time.Second) },
	})
	result = pastSkewVerifier.VerifyRequest(req, body, func(keyID string) (sigalg.ResolvedPublicKey, error) {
		return sigalg.ResolvedPublicKey{
			KeyID: keyID, Algorithm: sigalg.Ed25519, PublicKey: km.GetSigningKey().PublicKey,
			JWKKty: "OKP", JWKCrv: "Ed25519",
		}, nil
	})
	if result.Verified {
		t.Fatal("created past max skew should fail")
	}
	if result.Reason != crypto.ReasonFutureCreated {
		t.Fatalf("Reason=%q want future_created", result.Reason)
	}
}

func TestRFC9421_VerifyCreatedBoundaryAtMaxAge(t *testing.T) {
	km := crypto.NewKeyManager("", "https://example.com")
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatal(err)
	}

	signTime := time.Unix(1_730_815_200, 0)
	maxAge := time.Minute
	opts := crypto.DefaultRFC9421Options()
	opts.Now = func() time.Time { return signTime }
	opts.CreatedMaxAge = maxAge

	signer := crypto.NewRFC9421SignerWithOptions(km, opts)
	body := []byte(`{"test":"data"}`)
	req, _ := http.NewRequest("POST", "https://example.com/ocm/shares", bytes.NewReader(body))
	req.Host = "example.com"
	if err := signer.SignRequest(req, body); err != nil {
		t.Fatal(err)
	}

	atAgeVerifier := crypto.NewRFC9421VerifierWithOptions(crypto.RFC9421Options{
		Label:              opts.Label,
		CreatedMaxAge:      maxAge,
		CreatedMaxSkew:     opts.CreatedMaxSkew,
		AllowedAlgorithms:  opts.AllowedAlgorithms,
		RequiredComponents: opts.RequiredComponents,
		Now:                func() time.Time { return signTime.Add(maxAge) },
	})
	result := atAgeVerifier.VerifyRequest(req, body, func(keyID string) (sigalg.ResolvedPublicKey, error) {
		return sigalg.ResolvedPublicKey{
			KeyID: keyID, Algorithm: sigalg.Ed25519, PublicKey: km.GetSigningKey().PublicKey,
			JWKKty: "OKP", JWKCrv: "Ed25519",
		}, nil
	})
	if !result.Verified {
		t.Fatalf("created at max age should verify: %v", result.Error)
	}

	staleVerifier := crypto.NewRFC9421VerifierWithOptions(crypto.RFC9421Options{
		Label:              opts.Label,
		CreatedMaxAge:      maxAge,
		CreatedMaxSkew:     opts.CreatedMaxSkew,
		AllowedAlgorithms:  opts.AllowedAlgorithms,
		RequiredComponents: opts.RequiredComponents,
		Now:                func() time.Time { return signTime.Add(maxAge + time.Second) },
	})
	result = staleVerifier.VerifyRequest(req, body, func(keyID string) (sigalg.ResolvedPublicKey, error) {
		return sigalg.ResolvedPublicKey{
			KeyID: keyID, Algorithm: sigalg.Ed25519, PublicKey: km.GetSigningKey().PublicKey,
			JWKKty: "OKP", JWKCrv: "Ed25519",
		}, nil
	})
	if result.Verified {
		t.Fatal("created past max age should fail")
	}
	if result.Reason != crypto.ReasonStaleCreated {
		t.Fatalf("Reason=%q want stale_created", result.Reason)
	}
}

func TestHasSignatureHeaders(t *testing.T) {
	verifier := crypto.NewRFC9421Verifier()

	tests := []struct {
		name     string
		headers  map[string]string
		expected bool
	}{
		{"no headers", map[string]string{}, false},
		{"signature-input only", map[string]string{"Signature-Input": "test"}, true},
		{"signature only", map[string]string{"Signature": "test"}, true},
		{"both headers", map[string]string{"Signature-Input": "a", "Signature": "b"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/test", nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			if verifier.HasSignatureHeaders(req) != tt.expected {
				t.Errorf("HasSignatureHeaders = %v, want %v", !tt.expected, tt.expected)
			}
		})
	}
}

func TestVerifyRequest_RejectPaths(t *testing.T) {
	verifier := crypto.NewRFC9421Verifier()

	km := crypto.NewKeyManager("", "https://example.com")
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatalf("LoadOrGenerate failed: %v", err)
	}

	zeroSig := "ocm=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==:"

	keyFetcher := func(keyID string) (sigalg.ResolvedPublicKey, error) {
		return sigalg.ResolvedPublicKey{
			KeyID: keyID, Algorithm: sigalg.Ed25519, PublicKey: km.GetSigningKey().PublicKey,
			JWKKty: "OKP", JWKCrv: "Ed25519",
		}, nil
	}

	now := time.Now().Unix()
	validParams := fmt.Sprintf(
		`ocm=("@method" "@target-uri" "content-digest" "content-length" "date");created=%d;keyid=%q;alg="ed25519";tag="ocm"`,
		now,
		km.GetKeyID(),
	)

	tests := []struct {
		name           string
		signatureInput string
		signature      string
		fetcher        func(string) (sigalg.ResolvedPublicKey, error)
		wantErrSubstr  string
	}{
		{
			name:          "missing Signature-Input header",
			signature:     zeroSig,
			fetcher:       keyFetcher,
			wantErrSubstr: "missing Signature-Input",
		},
		{
			name:           "missing Signature header",
			signatureInput: validParams,
			fetcher:        keyFetcher,
			wantErrSubstr:  "missing Signature",
		},
		{
			name:           "missing created parameter",
			signatureInput: `ocm=("@method" "@target-uri" "content-digest" "content-length" "date");keyid="example.com#key1";alg="ed25519";tag="ocm"`,
			signature:      zeroSig,
			fetcher:        keyFetcher,
			wantErrSubstr:  "missing created",
		},
		{
			name:           "missing minimum component",
			signatureInput: fmt.Sprintf(`ocm=("@method");created=%d;keyid=%q;alg="ed25519";tag="ocm"`, now, km.GetKeyID()),
			signature:      zeroSig,
			fetcher:        keyFetcher,
			wantErrSubstr:  "missing required signature component",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "https://example.com/test", nil)
			req.Header.Set("Date", "Fri, 16 Jan 2026 13:37:00 GMT")
			if tt.signatureInput != "" {
				req.Header.Set("Signature-Input", tt.signatureInput)
			}
			if tt.signature != "" {
				req.Header.Set("Signature", tt.signature)
			}

			result := verifier.VerifyRequest(req, nil, tt.fetcher)

			if result.Verified {
				t.Error("expected Verified=false, got true")
			}
			if result.Error == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErrSubstr)
			}
			if !strings.Contains(result.Error.Error(), tt.wantErrSubstr) {
				t.Errorf("error = %q, want substring %q", result.Error.Error(), tt.wantErrSubstr)
			}
		})
	}
}

func TestAppendixBCoveredComponents(t *testing.T) {
	components := crypto.AppendixBCoveredComponents()
	want := []string{"@method", "@target-uri", "content-digest", "content-length", "date"}
	if len(components) != len(want) {
		t.Fatalf("components = %v", components)
	}
	for i, c := range want {
		if components[i] != c {
			t.Fatalf("components[%d] = %q, want %q", i, components[i], c)
		}
	}
}

func TestRFC9421OptionsFromConfig_NonDefaults(t *testing.T) {
	sig := config.SignatureConfig{
		Label:                 "customlabel",
		CreatedMaxAgeSeconds:  120,
		CreatedMaxSkewSeconds: 15,
		AllowedAlgorithms:     sigalg.DefaultAllowed(),
	}
	opts := crypto.RFC9421OptionsFromConfig(sig)
	if opts.Label != "customlabel" {
		t.Fatalf("Label = %q", opts.Label)
	}
	if opts.CreatedMaxAge != 120*time.Second {
		t.Fatalf("CreatedMaxAge = %v", opts.CreatedMaxAge)
	}
	if opts.CreatedMaxSkew != 15*time.Second {
		t.Fatalf("CreatedMaxSkew = %v", opts.CreatedMaxSkew)
	}
	if len(opts.AllowedAlgorithms) != len(sigalg.DefaultAllowed()) || opts.AllowedAlgorithms[0] != "ed25519" {
		t.Fatalf("AllowedAlgorithms = %v", opts.AllowedAlgorithms)
	}
}

func TestAppendixB_VectorSignVerify_Positive(t *testing.T) {
	fixedNow := time.Unix(1_730_815_200, 0)
	cases := []struct {
		name   string
		method string
		target string
		body   []byte
	}{
		{
			name:   "GET empty body includes all Appendix B components",
			method: "GET",
			target: "https://example.com/.well-known/ocm",
			body:   nil,
		},
		{
			name:   "POST with body includes Appendix B digest set",
			method: "POST",
			target: "https://example.com/ocm/shares",
			body:   []byte(`{"shareWith":"alice@peer.example"}`),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			km := crypto.NewKeyManager("", "https://example.com")
			if err := km.LoadOrGenerate(); err != nil {
				t.Fatal(err)
			}

			opts := crypto.DefaultRFC9421Options()
			opts.Now = func() time.Time { return fixedNow }

			signer := crypto.NewRFC9421SignerWithOptions(km, opts)
			verifier := crypto.NewRFC9421VerifierWithOptions(opts)

			var reqBody io.Reader = http.NoBody
			if tc.body != nil {
				reqBody = bytes.NewReader(tc.body)
			}
			req, err := http.NewRequest(tc.method, tc.target, reqBody)
			if err != nil {
				t.Fatal(err)
			}
			req.Host = "example.com"
			if len(tc.body) > 0 {
				req.Header.Set("Content-Type", "application/json")
			}

			if err := signer.SignRequest(req, tc.body); err != nil {
				t.Fatalf("SignRequest: %v", err)
			}

			sigInput := req.Header.Get("Signature-Input")
			if !strings.HasPrefix(sigInput, "ocm=") {
				t.Fatalf("Signature-Input = %q, want ocm= prefix", sigInput)
			}
			for _, want := range []string{"created=", `keyid=`, `alg="ed25519"`} {
				if !strings.Contains(sigInput, want) {
					t.Fatalf("Signature-Input missing %q: %q", want, sigInput)
				}
			}

			for _, want := range []string{`"@method"`, `"@target-uri"`, `"content-digest"`, `"content-length"`, `"date"`} {
				if !strings.Contains(sigInput, want) {
					t.Fatalf("Signature-Input missing %q: %q", want, sigInput)
				}
			}
			if len(tc.body) == 0 {
				wantDigest := "sha-256=:" + base64.StdEncoding.EncodeToString(sigalg.SumSHA256(nil)) + ":"
				if got := req.Header.Get("Content-Digest"); got != wantDigest {
					t.Errorf("Content-Digest = %q, want %q", got, wantDigest)
				}
				if got := req.Header.Get("Content-Length"); got != "0" {
					t.Errorf("Content-Length = %q, want 0", got)
				}
			}

			result := verifier.VerifyRequest(req, tc.body, func(keyID string) (sigalg.ResolvedPublicKey, error) {
				return sigalg.ResolvedPublicKey{
					KeyID: keyID, Algorithm: sigalg.Ed25519, PublicKey: km.GetSigningKey().PublicKey,
					JWKKty: "OKP", JWKCrv: "Ed25519",
				}, nil
			})
			if !result.Verified {
				t.Fatalf("verification failed: %v", result.Error)
			}
		})
	}
}

func TestAppendixB_VectorVerify_Negative(t *testing.T) {
	fixedNow := time.Unix(1_730_815_200, 0)
	km := crypto.NewKeyManager("", "https://example.com")
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatal(err)
	}

	opts := crypto.DefaultRFC9421Options()
	opts.Now = func() time.Time { return fixedNow }

	signer := crypto.NewRFC9421SignerWithOptions(km, opts)
	verifier := crypto.NewRFC9421VerifierWithOptions(opts)

	body := []byte(`{"test":"data"}`)
	req, err := http.NewRequest("POST", "https://example.com/ocm/token", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "example.com"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := signer.SignRequest(req, body); err != nil {
		t.Fatal(err)
	}

	keyFetcher := func(keyID string) (sigalg.ResolvedPublicKey, error) {
		return sigalg.ResolvedPublicKey{
			KeyID: keyID, Algorithm: sigalg.Ed25519, PublicKey: km.GetSigningKey().PublicKey,
			JWKKty: "OKP", JWKCrv: "Ed25519",
		}, nil
	}

	cases := []struct {
		name    string
		mutate  func(*http.Request)
		wantErr string
	}{
		{
			name: "wrong signature tag",
			mutate: func(r *http.Request) {
				r.Header.Set("Signature-Input", strings.Replace(r.Header.Get("Signature-Input"), `tag="ocm"`, `tag="other"`, 1))
			},
			wantErr: "tag",
		},
		{
			name: "changed method after signing",
			mutate: func(r *http.Request) {
				r.Method = http.MethodGet
			},
			wantErr: "verification failed",
		},
		{
			name: "stripped Signature header",
			mutate: func(r *http.Request) {
				r.Header.Del("Signature")
			},
			wantErr: "missing Signature",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cloned := req.Clone(req.Context())
			for k, vals := range req.Header {
				cloned.Header[k] = append([]string(nil), vals...)
			}
			tc.mutate(cloned)

			result := verifier.VerifyRequest(cloned, body, keyFetcher)
			if result.Verified {
				t.Fatal("expected verification failure")
			}
			if result.Error == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(strings.ToLower(result.Error.Error()), strings.ToLower(tc.wantErr)) {
				t.Fatalf("error = %v, want substring %q", result.Error, tc.wantErr)
			}
		})
	}
}

func TestVerifyRequest_MissingHeaderAlgUsesJWK(t *testing.T) {
	km := crypto.NewKeyManager("", "https://example.com")
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatal(err)
	}
	opts := crypto.DefaultRFC9421Options()
	verifier := crypto.NewRFC9421VerifierWithOptions(opts)

	body := []byte(`{"ok":true}`)
	req := httptest.NewRequest("POST", "https://example.com/ocm/shares", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Date", opts.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT"))
	digest := base64.StdEncoding.EncodeToString(sigalg.SumSHA256(body))
	req.Header.Set("Content-Digest", "sha-256=:"+digest+":")
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))

	components := []string{"@method", "@target-uri", "content-digest", "content-length", "date"}
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

	result := verifier.VerifyRequest(req, body, func(keyID string) (sigalg.ResolvedPublicKey, error) {
		return sigalg.ResolvedPublicKey{
			KeyID: keyID, Algorithm: sigalg.Ed25519, PublicKey: km.GetSigningKey().PublicKey,
			JWKKty: "OKP", JWKCrv: "Ed25519",
		}, nil
	})
	if !result.Verified {
		t.Fatalf("expected omit-alg verify OK, got %v", result.Error)
	}
}

func TestVerifyRequest_DoesNotFetchBeforeCreatedCheck(t *testing.T) {
	verifier := crypto.NewRFC9421Verifier()
	fetches := 0
	req := httptest.NewRequest("POST", "https://example.com/ocm/shares", nil)
	req.Header.Set("Date", "Fri, 16 Jan 2026 13:37:00 GMT")
	req.Header.Set("Signature-Input", `ocm=("@method" "@target-uri" "content-digest" "content-length" "date");keyid="example.com#key1";alg="ed25519";tag="ocm"`)
	req.Header.Set("Signature", "ocm=:AAAA:")

	result := verifier.VerifyRequest(req, nil, func(keyID string) (sigalg.ResolvedPublicKey, error) {
		fetches++
		return sigalg.ResolvedPublicKey{}, nil
	})
	if result.Verified {
		t.Fatal("expected failure")
	}
	if result.Reason != crypto.ReasonMissingCreated {
		t.Fatalf("Reason=%q want missing_created (err=%v)", result.Reason, result.Error)
	}
	if fetches != 0 {
		t.Fatalf("fetches=%d want 0 before created validation", fetches)
	}
}

func TestVerifyRequest_DoesNotFetchBeforeMissingComponents(t *testing.T) {
	verifier := crypto.NewRFC9421Verifier()
	fetches := 0
	now := time.Now().Unix()
	req := httptest.NewRequest("POST", "https://example.com/ocm/shares", nil)
	req.Header.Set("Date", "Fri, 16 Jan 2026 13:37:00 GMT")
	req.Header.Set("Signature-Input", fmt.Sprintf(
		`ocm=("@method" "@target-uri");created=%d;keyid="example.com#key1";alg="ed25519";tag="ocm"`,
		now,
	))
	req.Header.Set("Signature", "ocm=:AAAA:")

	result := verifier.VerifyRequest(req, nil, func(keyID string) (sigalg.ResolvedPublicKey, error) {
		fetches++
		return sigalg.ResolvedPublicKey{}, nil
	})
	if result.Verified {
		t.Fatal("expected failure")
	}
	if result.Reason != crypto.ReasonMissingComponent {
		t.Fatalf("Reason=%q want missing_component (err=%v)", result.Reason, result.Error)
	}
	if fetches != 0 {
		t.Fatalf("fetches=%d want 0 before component validation", fetches)
	}
}

func TestVerifyRequest_DoesNotFetchOnMalformedSignature(t *testing.T) {
	verifier := crypto.NewRFC9421Verifier()
	fetches := 0
	now := time.Now().Unix()
	req := httptest.NewRequest("POST", "https://example.com/ocm/shares", nil)
	req.Header.Set("Date", "Fri, 16 Jan 2026 13:37:00 GMT")
	req.Header.Set("Content-Digest", "sha-256=:AAAA:")
	req.Header.Set("Content-Length", "2")
	req.Header.Set("Signature-Input", fmt.Sprintf(
		`ocm=("@method" "@target-uri" "content-digest" "content-length" "date");created=%d;keyid="example.com#key1";alg="ed25519";tag="ocm"`,
		now,
	))
	req.Header.Set("Signature", "ocm=not-a-byte-sequence")

	result := verifier.VerifyRequest(req, []byte("{}"), func(keyID string) (sigalg.ResolvedPublicKey, error) {
		fetches++
		return sigalg.ResolvedPublicKey{}, nil
	})
	if result.Verified {
		t.Fatal("expected failure")
	}
	if result.Reason != crypto.ReasonMalformed {
		t.Fatalf("Reason=%q want malformed (err=%v)", result.Reason, result.Error)
	}
	if fetches != 0 {
		t.Fatalf("fetches=%d want 0 on malformed Signature", fetches)
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
	req := httptest.NewRequest("POST", "https://example.com/ocm/shares", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Date", opts.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT"))
	digest := base64.StdEncoding.EncodeToString(sigalg.SumSHA256(body))
	req.Header.Set("Content-Digest", "sha-256=:"+digest+":")
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))

	keyID := "example.com#ec1"
	components := []string{"@method", "@target-uri", "content-digest", "content-length", "date"}
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
	body := []byte(`{"test":"data"}`)
	digest := "sha-256=:" + base64.StdEncoding.EncodeToString(sigalg.SumSHA256(body)) + ":"

	newReq := func() *http.Request {
		req := httptest.NewRequest("POST", "https://example.com/ocm/shares", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Content-Digest", digest)
		req.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
		req.Header.Set("Date", "Fri, 16 Jan 2026 13:37:00 GMT")
		req.Header.Set("Signature-Input", fmt.Sprintf(
			`ocm=("@method" "@target-uri" "content-digest" "content-length" "date");created=%d;keyid="example.com#key1";alg="ed25519";tag="ocm"`,
			now,
		))
		req.Header.Set("Signature", "ocm=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:")
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

func TestVerifyRequest_RejectsDuplicateSignatureLabels(t *testing.T) {
	verifier := crypto.NewRFC9421Verifier()
	now := time.Now().Unix()
	body := []byte(`{"test":"data"}`)
	digest := "sha-256=:" + base64.StdEncoding.EncodeToString(sigalg.SumSHA256(body)) + ":"

	newReq := func(sigInput, signature string) *http.Request {
		req := httptest.NewRequest("POST", "https://example.com/ocm/shares", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Content-Digest", digest)
		req.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
		req.Header.Set("Date", "Fri, 16 Jan 2026 13:37:00 GMT")
		req.Header.Set("Signature-Input", sigInput)
		req.Header.Set("Signature", signature)
		return req
	}

	t.Run("duplicate_signature_input", func(t *testing.T) {
		fetched := false
		result := verifier.VerifyRequest(newReq(
			fmt.Sprintf(
				`ocm=("@method" "@target-uri" "content-digest" "content-length" "date");created=%d;keyid="a#1";alg="ed25519";tag="ocm", ocm=("@method" "@target-uri" "content-digest" "content-length" "date");created=%d;keyid="b#1";alg="ed25519";tag="ocm"`,
				now, now,
			),
			"ocm=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:",
		), body, func(string) (sigalg.ResolvedPublicKey, error) {
			fetched = true
			return sigalg.ResolvedPublicKey{}, fmt.Errorf("should not fetch key")
		})
		if result.Verified {
			t.Fatal("expected duplicate tag rejection")
		}
		if result.Reason != crypto.ReasonMalformed {
			t.Fatalf("Reason=%q want malformed (err=%v)", result.Reason, result.Error)
		}
		if result.Error == nil || !strings.Contains(result.Error.Error(), `multiple tag="ocm" signatures`) {
			t.Fatalf("error = %v, want multiple tag=\"ocm\" signatures", result.Error)
		}
		if fetched {
			t.Fatal("key fetch must not run after duplicate-tag rejection")
		}
	})

	t.Run("duplicate_signature", func(t *testing.T) {
		fetched := false
		result := verifier.VerifyRequest(newReq(
			fmt.Sprintf(
				`ocm=("@method" "@target-uri" "content-digest" "content-length" "date");created=%d;keyid="a#1";alg="ed25519";tag="ocm"`,
				now,
			),
			"ocm=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:, ocm=:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=:",
		), body, func(string) (sigalg.ResolvedPublicKey, error) {
			fetched = true
			return sigalg.ResolvedPublicKey{}, fmt.Errorf("should not fetch key")
		})
		if result.Verified {
			t.Fatal("expected duplicate Signature label rejection")
		}
		if result.Reason != crypto.ReasonMalformed {
			t.Fatalf("Reason=%q want malformed (err=%v)", result.Reason, result.Error)
		}
		if result.Error == nil || !strings.Contains(result.Error.Error(), `multiple "ocm" signatures`) {
			t.Fatalf("error = %v, want multiple ocm signatures", result.Error)
		}
		if fetched {
			t.Fatal("key fetch must not run after duplicate-label rejection")
		}
	})
}

func TestCanonicalTargetURI_ConsistentWithAndWithoutURLScheme(t *testing.T) {
	withScheme := httptest.NewRequest("POST", "https://example.com/ocm/shares?x=1", nil)
	withScheme.Host = "example.com"
	want := "https://example.com/ocm/shares?x=1"
	if got := crypto.CanonicalTargetURI(withScheme); got != want {
		t.Fatalf("with scheme: got %q want %q", got, want)
	}

	// Proxy-style request: path-only URL, Host set, no TLS -> http form.
	without := httptest.NewRequest("POST", "/ocm/shares?x=1", nil)
	without.Host = "example.com"
	without.URL.Scheme = ""
	without.URL.Host = ""
	got := crypto.CanonicalTargetURI(without)
	if got != "http://example.com/ocm/shares?x=1" {
		t.Fatalf("without scheme: got %q", got)
	}
}

func TestBuildSignatureBase_RejectsCRLFInComponent(t *testing.T) {
	req := httptest.NewRequest("POST", "https://example.com/ocm/shares", nil)
	req.Header.Set("date", "Fri, 16 Jan 2026 13:37:00 GMT\r\nX-Injected: 1")
	_, err := crypto.BuildSignatureBase(req, []string{"@method", "date"})
	if err == nil {
		t.Fatal("expected CR/LF rejection")
	}
}

func TestSignRequest_CoversAllComponentsOnEmptyBody(t *testing.T) {
	km := crypto.NewKeyManager("", "https://example.com")
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatal(err)
	}
	opts := crypto.DefaultRFC9421Options()
	opts.Now = func() time.Time { return time.Unix(1_730_815_200, 0) }
	signer := crypto.NewRFC9421SignerWithOptions(km, opts)

	req, err := http.NewRequest("GET", "https://example.com/ocm/discovery", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "example.com"

	if err := signer.SignRequest(req, nil); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}

	sigInput := req.Header.Get("Signature-Input")
	for _, want := range []string{`"@method"`, `"@target-uri"`, `"content-digest"`, `"content-length"`, `"date"`} {
		if !strings.Contains(sigInput, want) {
			t.Fatalf("empty-body Signature-Input missing %s: %q", want, sigInput)
		}
	}

	wantDigest := "sha-256=:" + base64.StdEncoding.EncodeToString(sigalg.SumSHA256(nil)) + ":"
	if got := req.Header.Get("Content-Digest"); got != wantDigest {
		t.Errorf("Content-Digest = %q, want %q", got, wantDigest)
	}
	if got := req.Header.Get("Content-Length"); got != "0" {
		t.Errorf("Content-Length = %q, want 0", got)
	}
}

func TestSignRequest_CoversAllComponentsOnNonEmptyBody(t *testing.T) {
	km := crypto.NewKeyManager("", "https://example.com")
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatal(err)
	}
	opts := crypto.DefaultRFC9421Options()
	opts.Now = func() time.Time { return time.Unix(1_730_815_200, 0) }
	signer := crypto.NewRFC9421SignerWithOptions(km, opts)

	body := []byte(`{"test":"data"}`)
	req, err := http.NewRequest("POST", "https://example.com/ocm/shares", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "example.com"

	if err := signer.SignRequest(req, body); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}

	sigInput := req.Header.Get("Signature-Input")
	for _, want := range []string{`"@method"`, `"@target-uri"`, `"content-digest"`, `"content-length"`, `"date"`} {
		if !strings.Contains(sigInput, want) {
			t.Fatalf("Signature-Input missing %s: %q", want, sigInput)
		}
	}
}

func TestVerifyRequest_RequiresAllComponentsOnEmptyBody(t *testing.T) {
	km := crypto.NewKeyManager("", "https://example.com")
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatal(err)
	}
	opts := crypto.DefaultRFC9421Options()
	opts.Now = func() time.Time { return time.Unix(1_730_815_200, 0) }
	verifier := crypto.NewRFC9421VerifierWithOptions(opts)

	tests := []struct {
		name       string
		components []string
	}{
		{
			name:       "missing @method",
			components: []string{"@target-uri", "content-digest", "content-length", "date"},
		},
		{
			name:       "missing @target-uri",
			components: []string{"@method", "content-digest", "content-length", "date"},
		},
		{
			name:       "missing content-digest",
			components: []string{"@method", "@target-uri", "content-length", "date"},
		},
		{
			name:       "missing content-length",
			components: []string{"@method", "@target-uri", "content-digest", "date"},
		},
		{
			name:       "missing date",
			components: []string{"@method", "@target-uri", "content-digest", "content-length"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "https://example.com/ocm/discovery", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Host = "example.com"
			req.Header.Set(
				"Content-Digest",
				"sha-256=:"+base64.StdEncoding.EncodeToString(sigalg.SumSHA256(nil))+":",
			)
			req.Header.Set("Content-Length", "0")
			req.Header.Set("Date", opts.Now().UTC().Format(http.TimeFormat))

			sigInput := fmt.Sprintf(
				`ocm=("%s");created=%d;keyid=%q;alg="ed25519";tag="ocm"`,
				strings.Join(tc.components, `" "`),
				opts.Now().Unix(),
				km.GetKeyID(),
			)
			sigBase, err := crypto.BuildSignatureBase(req, tc.components)
			if err != nil {
				t.Fatalf("BuildSignatureBase: %v", err)
			}
			paramsRaw := strings.TrimPrefix(sigInput, "ocm=")
			fullBase := sigBase + fmt.Sprintf(`"@signature-params": %s`, paramsRaw)
			sig, err := km.Sign([]byte(fullBase))
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			req.Header.Set("Signature-Input", sigInput)
			req.Header.Set(
				"Signature",
				fmt.Sprintf("ocm=:%s:", base64.StdEncoding.EncodeToString(sig)),
			)

			result := verifier.VerifyRequest(req, nil, func(keyID string) (sigalg.ResolvedPublicKey, error) {
				return sigalg.ResolvedPublicKey{
					KeyID: keyID, Algorithm: sigalg.Ed25519, PublicKey: km.GetSigningKey().PublicKey,
					JWKKty: "OKP", JWKCrv: "Ed25519",
				}, nil
			})
			if result.Verified {
				t.Fatal("expected verification failure when a body component is omitted")
			}
		})
	}
}

func TestVerifyRequest_AcceptsForeignLabelsWithOneOCM(t *testing.T) {
	km := crypto.NewKeyManager("", "https://example.com")
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatal(err)
	}
	opts := crypto.DefaultRFC9421Options()
	opts.Now = func() time.Time { return time.Unix(1_730_815_200, 0) }
	signer := crypto.NewRFC9421SignerWithOptions(km, opts)
	verifier := crypto.NewRFC9421VerifierWithOptions(opts)

	body := []byte(`{"test":"data"}`)
	req, err := http.NewRequest("POST", "https://example.com/ocm/shares", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "example.com"
	if err := signer.SignRequest(req, body); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}

	foreignSigInput := `sig1=("@method" "@target-uri" "content-digest" "content-length" "date");created=1;keyid="foreign.example#k1";alg="ed25519"`
	foreignSignature := "sig1=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:"
	req.Header.Set("Signature-Input", foreignSigInput+", "+req.Header.Get("Signature-Input"))
	req.Header.Set("Signature", foreignSignature+", "+req.Header.Get("Signature"))

	result := verifier.VerifyRequest(req, body, func(keyID string) (sigalg.ResolvedPublicKey, error) {
		return sigalg.ResolvedPublicKey{
			KeyID: keyID, Algorithm: sigalg.Ed25519, PublicKey: km.GetSigningKey().PublicKey,
			JWKKty: "OKP", JWKCrv: "Ed25519",
		}, nil
	})
	if !result.Verified {
		t.Fatalf("expected verification of the ocm member alongside an ignored foreign label, got verified=false reason=%s err=%v", result.Reason, result.Error)
	}
	if result.KeyID != km.GetKeyID() {
		t.Errorf("KeyID = %q, want %q", result.KeyID, km.GetKeyID())
	}
}

func TestVerifyRequest_RejectsDuplicateOCM(t *testing.T) {
	verifier := crypto.NewRFC9421Verifier()
	now := time.Now().Unix()
	body := []byte(`{"test":"data"}`)
	digest := "sha-256=:" + base64.StdEncoding.EncodeToString(sigalg.SumSHA256(body)) + ":"

	req := httptest.NewRequest("POST", "https://example.com/ocm/shares", bytes.NewReader(body))
	req.Header.Set("Content-Digest", digest)
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
	req.Header.Set("Date", "Fri, 16 Jan 2026 13:37:00 GMT")
	req.Header.Set("Signature-Input", fmt.Sprintf(
		`ocm=("@method" "@target-uri" "content-digest" "content-length" "date");created=%d;keyid="a#1";alg="ed25519";tag="ocm", ocm=("@method" "@target-uri" "content-digest" "content-length" "date");created=%d;keyid="b#1";alg="ed25519";tag="ocm"`,
		now, now,
	))
	req.Header.Set("Signature", "ocm=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:")

	fetched := false
	result := verifier.VerifyRequest(req, body, func(string) (sigalg.ResolvedPublicKey, error) {
		fetched = true
		return sigalg.ResolvedPublicKey{}, fmt.Errorf("should not fetch key")
	})
	if result.Verified {
		t.Fatal("expected duplicate ocm member rejection")
	}
	if fetched {
		t.Fatal("key fetch must not run after duplicate ocm member rejection")
	}
}

func TestVerifyRequest_RejectsMissingOCM(t *testing.T) {
	verifier := crypto.NewRFC9421Verifier()
	now := time.Now().Unix()
	req := httptest.NewRequest("POST", "https://example.com/ocm/shares", nil)
	req.Header.Set("Date", "Fri, 16 Jan 2026 13:37:00 GMT")
	req.Header.Set("Signature-Input", fmt.Sprintf(
		`sig1=("@method" "@target-uri" "date");created=%d;keyid="a#1";alg="ed25519"`,
		now,
	))
	req.Header.Set("Signature", "sig1=:AAAA:")

	fetched := false
	result := verifier.VerifyRequest(req, nil, func(string) (sigalg.ResolvedPublicKey, error) {
		fetched = true
		return sigalg.ResolvedPublicKey{}, fmt.Errorf("should not fetch key")
	})
	if result.Verified {
		t.Fatal("expected rejection when no ocm member is present")
	}
	if result.Error == nil || !strings.Contains(result.Error.Error(), "ocm") {
		t.Fatalf("error = %v, want missing ocm member", result.Error)
	}
	if fetched {
		t.Fatal("key fetch must not run when no ocm member is present")
	}
}

func TestVerifyRequest_RejectsMissingCreated(t *testing.T) {
	verifier := crypto.NewRFC9421Verifier()
	req := httptest.NewRequest("POST", "https://example.com/ocm/shares", nil)
	req.Header.Set("Date", "Fri, 16 Jan 2026 13:37:00 GMT")
	req.Header.Set("Signature-Input", `ocm=("@method" "@target-uri" "date");keyid="a#1";alg="ed25519";tag="ocm"`)
	req.Header.Set("Signature", "ocm=:AAAA:")

	result := verifier.VerifyRequest(req, nil, func(string) (sigalg.ResolvedPublicKey, error) {
		return sigalg.ResolvedPublicKey{}, nil
	})
	if result.Verified {
		t.Fatal("expected rejection when the created parameter is missing")
	}
	if result.Reason != crypto.ReasonMissingCreated {
		t.Fatalf("Reason = %q, want %q", result.Reason, crypto.ReasonMissingCreated)
	}
}

func TestVerifyRequest_RejectsFutureCreated(t *testing.T) {
	km := crypto.NewKeyManager("", "https://example.com")
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatal(err)
	}
	signTime := time.Unix(1_730_815_200, 0)
	verifyTime := signTime.Add(-2 * time.Minute)

	opts := crypto.DefaultRFC9421Options()
	opts.Now = func() time.Time { return signTime }
	opts.CreatedMaxSkew = time.Minute
	signer := crypto.NewRFC9421SignerWithOptions(km, opts)

	body := []byte(`{"test":"data"}`)
	req, err := http.NewRequest("POST", "https://example.com/ocm/shares", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "example.com"
	if err := signer.SignRequest(req, body); err != nil {
		t.Fatal(err)
	}

	verifier := crypto.NewRFC9421VerifierWithOptions(crypto.RFC9421Options{
		Label:              opts.Label,
		CreatedMaxAge:      opts.CreatedMaxAge,
		CreatedMaxSkew:     opts.CreatedMaxSkew,
		AllowedAlgorithms:  opts.AllowedAlgorithms,
		RequiredComponents: opts.RequiredComponents,
		Now:                func() time.Time { return verifyTime },
	})
	result := verifier.VerifyRequest(req, body, func(keyID string) (sigalg.ResolvedPublicKey, error) {
		return sigalg.ResolvedPublicKey{
			KeyID: keyID, Algorithm: sigalg.Ed25519, PublicKey: km.GetSigningKey().PublicKey,
			JWKKty: "OKP", JWKCrv: "Ed25519",
		}, nil
	})
	if result.Verified {
		t.Fatal("expected future created to fail verification")
	}
	if result.Reason != crypto.ReasonFutureCreated {
		t.Fatalf("Reason = %q, want %q", result.Reason, crypto.ReasonFutureCreated)
	}
}

func TestVerifyRequest_RejectsStaleCreated(t *testing.T) {
	km := crypto.NewKeyManager("", "https://example.com")
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_730_815_200, 0)
	opts := crypto.DefaultRFC9421Options()
	opts.Now = func() time.Time { return now }
	opts.CreatedMaxAge = time.Minute
	signer := crypto.NewRFC9421SignerWithOptions(km, opts)

	body := []byte(`{"test":"data"}`)
	req, err := http.NewRequest("POST", "https://example.com/ocm/shares", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "example.com"
	if err := signer.SignRequest(req, body); err != nil {
		t.Fatal(err)
	}

	verifier := crypto.NewRFC9421VerifierWithOptions(crypto.RFC9421Options{
		Label:              opts.Label,
		CreatedMaxAge:      opts.CreatedMaxAge,
		CreatedMaxSkew:     opts.CreatedMaxSkew,
		AllowedAlgorithms:  opts.AllowedAlgorithms,
		RequiredComponents: opts.RequiredComponents,
		Now:                func() time.Time { return now.Add(2 * time.Minute) },
	})
	result := verifier.VerifyRequest(req, body, func(keyID string) (sigalg.ResolvedPublicKey, error) {
		return sigalg.ResolvedPublicKey{
			KeyID: keyID, Algorithm: sigalg.Ed25519, PublicKey: km.GetSigningKey().PublicKey,
			JWKKty: "OKP", JWKCrv: "Ed25519",
		}, nil
	})
	if result.Verified {
		t.Fatal("expected stale created to fail verification")
	}
	if result.Reason != crypto.ReasonStaleCreated {
		t.Fatalf("Reason = %q, want %q", result.Reason, crypto.ReasonStaleCreated)
	}
}

func TestSignVerifyRoundTrip_RealTransport(t *testing.T) {
	km := crypto.NewKeyManager("", "https://example.com")
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatal(err)
	}
	opts := crypto.DefaultRFC9421Options()
	signer := crypto.NewRFC9421SignerWithOptions(km, opts)
	verifier := crypto.NewRFC9421VerifierWithOptions(opts)

	var gotSignatureInput string
	var gotVerified bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSignatureInput = r.Header.Get("Signature-Input")
		result := verifier.VerifyRequest(r, nil, func(keyID string) (sigalg.ResolvedPublicKey, error) {
			return sigalg.ResolvedPublicKey{
				KeyID: keyID, Algorithm: sigalg.Ed25519, PublicKey: km.GetSigningKey().PublicKey,
				JWKKty: "OKP", JWKCrv: "Ed25519",
			}, nil
		})
		gotVerified = result.Verified
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	req, err := http.NewRequest("GET", server.URL+"/ocm/discovery", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := signer.SignRequest(req, nil); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}

	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	defer resp.Body.Close()

	if !strings.Contains(gotSignatureInput, `"content-length"`) {
		t.Fatalf("server-observed Signature-Input = %q, want content-length coverage for an empty body", gotSignatureInput)
	}
	if !gotVerified {
		t.Fatal("expected server-side verification of the empty-body request to succeed")
	}
}

func padCoordTest(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}

func TestVerifyRequest_AcceptsEmptyBodyMissingContentLengthHeader(t *testing.T) {
	km := crypto.NewKeyManager("", "https://example.com")
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatal(err)
	}
	opts := crypto.DefaultRFC9421Options()
	opts.Now = func() time.Time { return time.Unix(1_730_815_200, 0) }
	verifier := crypto.NewRFC9421VerifierWithOptions(opts)

	req := httptest.NewRequest("GET", "https://example.com/ocm/discovery", nil)
	req.Host = "example.com"
	req.Header.Set("Date", opts.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT"))
	emptyDigest := base64.StdEncoding.EncodeToString(sigalg.SumSHA256(nil))
	req.Header.Set("Content-Digest", "sha-256=:"+emptyDigest+":")
	// Deliberately do NOT set Content-Length; req.ContentLength defaults to 0.

	components := []string{"@method", "@target-uri", "content-digest", "content-length", "date"}
	created := opts.Now().Unix()
	sigInput := fmt.Sprintf(
		`ocm=("@method" "@target-uri" "content-digest" "content-length" "date");created=%d;keyid=%q;alg="ed25519";tag="ocm"`,
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

	result := verifier.VerifyRequest(req, nil, func(keyID string) (sigalg.ResolvedPublicKey, error) {
		return sigalg.ResolvedPublicKey{
			KeyID: keyID, Algorithm: sigalg.Ed25519, PublicKey: km.GetSigningKey().PublicKey,
			JWKKty: "OKP", JWKCrv: "Ed25519",
		}, nil
	})
	if !result.Verified {
		t.Fatalf("expected empty-body verify OK with missing Content-Length header (canonical fallback), got verified=false reason=%s err=%v", result.Reason, result.Error)
	}
}

func TestVerifyRequest_RejectsNonEmptyBodyMissingContentLengthHeader(t *testing.T) {
	verifier := crypto.NewRFC9421Verifier()
	now := time.Now().Unix()
	body := []byte(`{"test":"data"}`)
	digest := "sha-256=:" + base64.StdEncoding.EncodeToString(sigalg.SumSHA256(body)) + ":"

	req := httptest.NewRequest("POST", "https://example.com/ocm/shares", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Digest", digest)
	// Deliberately do NOT set Content-Length.
	req.Header.Set("Date", "Fri, 16 Jan 2026 13:37:00 GMT")
	req.Header.Set("Signature-Input", fmt.Sprintf(
		`ocm=("@method" "@target-uri" "content-digest" "content-length" "date");created=%d;keyid="example.com#key1";alg="ed25519";tag="ocm"`,
		now,
	))
	req.Header.Set("Signature", "ocm=:AAAA:")

	fetched := false
	result := verifier.VerifyRequest(req, body, func(string) (sigalg.ResolvedPublicKey, error) {
		fetched = true
		return sigalg.ResolvedPublicKey{}, fmt.Errorf("should not fetch")
	})
	if result.Verified {
		t.Fatal("expected missing Content-Length rejection on non-empty body")
	}
	if result.Reason != crypto.ReasonContentDigest {
		t.Fatalf("Reason=%q want content_digest (err=%v)", result.Reason, result.Error)
	}
	if fetched {
		t.Fatal("key fetch must not run after missing Content-Length rejection")
	}
}

func TestHTTPSig_Sign_AlwaysEmitsTag(t *testing.T) {
	km := crypto.NewKeyManager("", "https://example.com")
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatalf("LoadOrGenerate failed: %v", err)
	}

	opts := crypto.DefaultRFC9421Options()
	opts.Now = func() time.Time { return time.Unix(1_730_815_200, 0) }

	signer := crypto.NewRFC9421SignerWithOptions(km, opts)

	body := []byte(`{"test":"data"}`)
	req, err := http.NewRequest("POST", "https://example.com/ocm/shares", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}
	req.Host = "example.com"

	if err := signer.SignRequest(req, body); err != nil {
		t.Fatalf("SignRequest failed: %v", err)
	}

	sigInput := req.Header.Get("Signature-Input")
	if strings.Count(sigInput, `tag="ocm"`) != 1 {
		t.Fatalf("Signature-Input must contain exactly one tag=\"ocm\": %q", sigInput)
	}
	if !strings.HasSuffix(sigInput, `;tag="ocm"`) {
		t.Fatalf("tag=\"ocm\" must be appended at the end: %q", sigInput)
	}

	verifier := crypto.NewRFC9421VerifierWithOptions(opts)
	result := verifier.VerifyRequest(req, body, func(keyID string) (sigalg.ResolvedPublicKey, error) {
		return sigalg.ResolvedPublicKey{
			KeyID: keyID, Algorithm: sigalg.Ed25519, PublicKey: km.GetSigningKey().PublicKey,
			JWKKty: "OKP", JWKCrv: "Ed25519",
		}, nil
	})
	if !result.Verified {
		t.Fatalf("verification of signed request with tag failed: %v", result.Error)
	}
}

func TestHTTPSig_Sign_AlwaysEmitsTagWithCustomLabel(t *testing.T) {
	km := crypto.NewKeyManager("", "https://example.com")
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatalf("LoadOrGenerate failed: %v", err)
	}

	opts := crypto.DefaultRFC9421Options()
	opts.Now = func() time.Time { return time.Unix(1_730_815_200, 0) }
	opts.Label = "customlabel"

	signer := crypto.NewRFC9421SignerWithOptions(km, opts)

	body := []byte(`{"test":"data"}`)
	req, err := http.NewRequest("POST", "https://example.com/ocm/shares", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}
	req.Host = "example.com"

	if err := signer.SignRequest(req, body); err != nil {
		t.Fatalf("SignRequest failed: %v", err)
	}

	sigInput := req.Header.Get("Signature-Input")
	if !strings.HasPrefix(sigInput, "customlabel=") {
		t.Fatalf("Signature-Input = %q, want customlabel= prefix", sigInput)
	}
	if strings.Count(sigInput, `tag="ocm"`) != 1 {
		t.Fatalf("Signature-Input must contain exactly one tag=\"ocm\": %q", sigInput)
	}
	if !strings.HasSuffix(sigInput, `;tag="ocm"`) {
		t.Fatalf("tag=\"ocm\" must be appended at the end: %q", sigInput)
	}

	verifier := crypto.NewRFC9421VerifierWithOptions(opts)
	result := verifier.VerifyRequest(req, body, func(keyID string) (sigalg.ResolvedPublicKey, error) {
		return sigalg.ResolvedPublicKey{
			KeyID: keyID, Algorithm: sigalg.Ed25519, PublicKey: km.GetSigningKey().PublicKey,
			JWKKty: "OKP", JWKCrv: "Ed25519",
		}, nil
	})
	if !result.Verified {
		t.Fatalf("verification of signed request with custom label failed: %v", result.Error)
	}
}

func TestHTTPSig_Verify_ByTag_IgnoresLabel(t *testing.T) {
	km := crypto.NewKeyManager("", "https://example.com")
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatalf("LoadOrGenerate failed: %v", err)
	}

	signOpts := crypto.DefaultRFC9421Options()
	signOpts.Now = func() time.Time { return time.Unix(1_730_815_200, 0) }
	signOpts.Label = "not-ocm"

	signer := crypto.NewRFC9421SignerWithOptions(km, signOpts)
	verifyOpts := crypto.DefaultRFC9421Options()
	verifyOpts.Now = signOpts.Now
	verifier := crypto.NewRFC9421VerifierWithOptions(verifyOpts)

	body := []byte(`{"test":"data"}`)
	req, err := http.NewRequest("POST", "https://example.com/ocm/shares", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}
	req.Host = "example.com"

	if err := signer.SignRequest(req, body); err != nil {
		t.Fatalf("SignRequest failed: %v", err)
	}

	sigInput := req.Header.Get("Signature-Input")
	if !strings.HasPrefix(sigInput, "not-ocm=") {
		t.Fatalf("Signature-Input = %q, want not-ocm= prefix", sigInput)
	}

	result := verifier.VerifyRequest(req, body, func(keyID string) (sigalg.ResolvedPublicKey, error) {
		return sigalg.ResolvedPublicKey{
			KeyID: keyID, Algorithm: sigalg.Ed25519, PublicKey: km.GetSigningKey().PublicKey,
			JWKKty: "OKP", JWKCrv: "Ed25519",
		}, nil
	})
	if !result.Verified {
		t.Fatalf("expected verification by tag to ignore label, got verified=false reason=%s err=%v", result.Reason, result.Error)
	}
	if result.KeyID != km.GetKeyID() {
		t.Errorf("KeyID = %q, want %q", result.KeyID, km.GetKeyID())
	}
}

func TestHTTPSig_Verify_TagCount(t *testing.T) {
	km := crypto.NewKeyManager("", "https://example.com")
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatalf("LoadOrGenerate failed: %v", err)
	}
	opts := crypto.DefaultRFC9421Options()
	opts.Now = func() time.Time { return time.Unix(1_730_815_200, 0) }
	verifier := crypto.NewRFC9421VerifierWithOptions(opts)

	body := []byte(`{"test":"data"}`)
	digest := "sha-256=:" + base64.StdEncoding.EncodeToString(sigalg.SumSHA256(body)) + ":"
	newReq := func(sigInput string) *http.Request {
		req := httptest.NewRequest("POST", "https://example.com/ocm/shares", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Content-Digest", digest)
		req.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
		req.Header.Set("Date", "Fri, 16 Jan 2026 13:37:00 GMT")
		req.Header.Set("Signature-Input", sigInput)
		req.Header.Set("Signature", "ocm=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:")
		return req
	}

	tests := []struct {
		name       string
		sigInput   string
		wantReason string
	}{
		{
			name:       "zero tags gives unsigned",
			sigInput:   `sig1=("@method" "@target-uri" "content-digest" "content-length" "date");created=1730815200;keyid="example.com#key1";alg="ed25519"`,
			wantReason: crypto.ReasonUnsigned,
		},
		{
			name:       "zero tags with foreign label and ocm label miss",
			sigInput:   `sig1=("@method" "@target-uri" "content-digest" "content-length" "date");created=1730815200;keyid="foreign.example#key1";alg="ed25519", ocm=("@method" "@target-uri" "content-digest" "content-length" "date");created=1730815200;keyid="example.com#key1";alg="ed25519"`,
			wantReason: crypto.ReasonUnsigned,
		},
		{
			name: "more than one tag rejects",
			sigInput: fmt.Sprintf(
				`ocm=("@method" "@target-uri" "content-digest" "content-length" "date");created=%d;keyid="a#1";alg="ed25519";tag="ocm", ocm=("@method" "@target-uri" "content-digest" "content-length" "date");created=%d;keyid="b#1";alg="ed25519";tag="ocm"`,
				opts.Now().Unix(), opts.Now().Unix(),
			),
			wantReason: crypto.ReasonMalformed,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := verifier.VerifyRequest(newReq(tc.sigInput), body, func(string) (sigalg.ResolvedPublicKey, error) {
				return sigalg.ResolvedPublicKey{}, fmt.Errorf("should not fetch key")
			})
			if result.Verified {
				t.Fatal("expected verification failure")
			}
			if result.Reason != tc.wantReason {
				t.Fatalf("Reason=%q, want %q (err=%v)", result.Reason, tc.wantReason, result.Error)
			}
		})
	}
}

func TestHTTPSig_Verify_TagIntegrityInvariant(t *testing.T) {
	km := crypto.NewKeyManager("", "https://example.com")
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatalf("LoadOrGenerate failed: %v", err)
	}

	opts := crypto.DefaultRFC9421Options()
	opts.Now = func() time.Time { return time.Unix(1_730_815_200, 0) }
	opts.Label = "integritylabel"
	signer := crypto.NewRFC9421SignerWithOptions(km, opts)
	verifier := crypto.NewRFC9421VerifierWithOptions(opts)

	body := []byte(`{"test":"data"}`)
	req, err := http.NewRequest("POST", "https://example.com/ocm/shares", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}
	req.Host = "example.com"

	if err := signer.SignRequest(req, body); err != nil {
		t.Fatalf("SignRequest failed: %v", err)
	}

	sigInput := req.Header.Get("Signature-Input")
	if !strings.HasPrefix(sigInput, "integritylabel=") {
		t.Fatalf("Signature-Input = %q, want integritylabel= prefix", sigInput)
	}
	if !strings.Contains(sigInput, `;tag="ocm"`) {
		t.Fatalf("Signature-Input must include tag parameter: %q", sigInput)
	}

	result := verifier.VerifyRequest(req, body, func(keyID string) (sigalg.ResolvedPublicKey, error) {
		return sigalg.ResolvedPublicKey{
			KeyID: keyID, Algorithm: sigalg.Ed25519, PublicKey: km.GetSigningKey().PublicKey,
			JWKKty: "OKP", JWKCrv: "Ed25519",
		}, nil
	})
	if !result.Verified {
		t.Fatalf("expected verification with tag preserved, got verified=false reason=%s err=%v", result.Reason, result.Error)
	}

	label, err := sigparams.FindTaggedLabel(sigInput, sigparams.SignatureTagOCM)
	if err != nil {
		t.Fatalf("FindTaggedLabel: %v", err)
	}
	params, err := sigparams.ParseSignatureInput(sigInput, label)
	if err != nil {
		t.Fatalf("ParseSignatureInput: %v", err)
	}
	if !strings.Contains(params.Raw, `;tag="ocm"`) {
		t.Fatalf("@signature-params raw entry must preserve tag: %q", params.Raw)
	}
}

func TestHTTPSig_GoldenDefaultSignatureInput(t *testing.T) {
	km := crypto.NewKeyManager("", "https://example.com")
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatalf("LoadOrGenerate failed: %v", err)
	}

	opts := crypto.DefaultRFC9421Options()
	opts.Now = func() time.Time { return time.Unix(1_730_815_200, 0) }
	signer := crypto.NewRFC9421SignerWithOptions(km, opts)

	body := []byte(`{"test":"data"}`)
	req, err := http.NewRequest("POST", "https://example.com/ocm/shares", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}
	req.Host = "example.com"
	req.Header.Set("Content-Type", "application/json")

	if err := signer.SignRequest(req, body); err != nil {
		t.Fatalf("SignRequest failed: %v", err)
	}

	sigInput := req.Header.Get("Signature-Input")
	goldenRe := regexp.MustCompile(
		`^ocm=\("@method" "@target-uri" "content-digest" "content-length" "date"\);created=1730815200;keyid="[^"]+";alg="ed25519";tag="ocm"$`,
	)
	if !goldenRe.MatchString(sigInput) {
		t.Fatalf("Signature-Input = %q, does not match golden default pattern", sigInput)
	}
}
