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
	"strings"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/jwks"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigalg"
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
	for _, unwanted := range []string{`"content-digest"`, `"content-length"`} {
		if strings.Contains(sigInput, unwanted) {
			t.Fatalf("empty-body Signature-Input should omit %s: %q", unwanted, sigInput)
		}
	}
	for _, want := range []string{`"@method"`, `"@target-uri"`, `"date"`} {
		if !strings.Contains(sigInput, want) {
			t.Fatalf("empty-body Signature-Input missing %s: %q", want, sigInput)
		}
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
	req.Header.Set("Signature-Input", fmt.Sprintf(
		`ocm=("@method" "@target-uri" "content-digest" "content-length" "date");created=%d;keyid="example.com#key1";alg="hmac-sha256"`,
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
		`ocm=("@method" "@target-uri" "content-digest" "content-length" "date");created=%d;keyid=%q;alg="ed25519"`,
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
			signatureInput: `ocm=("@method" "@target-uri" "content-digest" "content-length" "date");keyid="example.com#key1";alg="ed25519"`,
			signature:      zeroSig,
			fetcher:        keyFetcher,
			wantErrSubstr:  "missing created",
		},
		{
			name:           "missing minimum component",
			signatureInput: fmt.Sprintf(`ocm=("@method");created=%d;keyid=%q;alg="ed25519"`, now, km.GetKeyID()),
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
			name:   "GET empty body omits digest components",
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

			if len(tc.body) == 0 {
				for _, unwanted := range []string{`"content-digest"`, `"content-length"`} {
					if strings.Contains(sigInput, unwanted) {
						t.Fatalf("empty-body Signature-Input should omit %s: %q", unwanted, sigInput)
					}
				}
			} else {
				for _, want := range []string{`"content-digest"`, `"content-length"`} {
					if !strings.Contains(sigInput, want) {
						t.Fatalf("body Signature-Input missing %q: %q", want, sigInput)
					}
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
			name: "wrong signature label",
			mutate: func(r *http.Request) {
				r.Header.Set("Signature-Input", strings.Replace(r.Header.Get("Signature-Input"), "ocm=", "other=", 1))
				r.Header.Set("Signature", strings.Replace(r.Header.Get("Signature"), "ocm=", "other=", 1))
			},
			wantErr: "label",
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
		`ocm=("@method" "@target-uri" "content-digest" "content-length" "date");created=%d;keyid=%q`,
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
	req.Header.Set("Signature-Input", `ocm=("@method" "@target-uri" "content-digest" "content-length" "date");keyid="example.com#key1";alg="ed25519"`)
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
		`ocm=("@method" "@target-uri");created=%d;keyid="example.com#key1";alg="ed25519"`,
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
		`ocm=("@method" "@target-uri" "content-digest" "content-length" "date");created=%d;keyid="example.com#key1";alg="ed25519"`,
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
		`ocm=("@method" "@target-uri" "content-digest" "content-length" "date");created=%d;keyid=%q`,
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
			`ocm=("@method" "@target-uri" "content-digest" "content-length" "date");created=%d;keyid="example.com#key1";alg="ed25519"`,
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

func TestVerifyRequest_RejectsDuplicateDictionaryLabel(t *testing.T) {
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
				`ocm=("@method" "@target-uri" "content-digest" "content-length" "date");created=%d;keyid="a#1";alg="ed25519", ocm=("@method" "@target-uri" "content-digest" "content-length" "date");created=%d;keyid="b#1";alg="ed25519"`,
				now, now,
			),
			"ocm=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:",
		), body, func(string) (sigalg.ResolvedPublicKey, error) {
			fetched = true
			return sigalg.ResolvedPublicKey{}, fmt.Errorf("should not fetch key")
		})
		if result.Verified {
			t.Fatal("expected duplicate label rejection")
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

	t.Run("duplicate_signature", func(t *testing.T) {
		fetched := false
		result := verifier.VerifyRequest(newReq(
			fmt.Sprintf(
				`ocm=("@method" "@target-uri" "content-digest" "content-length" "date");created=%d;keyid="a#1";alg="ed25519"`,
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

func padCoordTest(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}
