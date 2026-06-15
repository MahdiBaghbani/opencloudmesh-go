package crypto_test

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
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

	result := verifier.VerifyRequest(req, nil, func(keyID string) (ed25519.PublicKey, error) {
		return km.GetSigningKey().PublicKey, nil
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

	result := verifier.VerifyRequest(req, body, func(keyID string) (ed25519.PublicKey, error) {
		return km.GetSigningKey().PublicKey, nil
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

	result := verifier.VerifyRequest(req, nil, func(keyID string) (ed25519.PublicKey, error) {
		return nil, nil
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

	result := verifier.VerifyRequest(req, body, func(keyID string) (ed25519.PublicKey, error) {
		return km2.GetSigningKey().PublicKey, nil
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

	result := staleVerifier.VerifyRequest(req, body, func(keyID string) (ed25519.PublicKey, error) {
		return km.GetSigningKey().PublicKey, nil
	})
	if result.Verified {
		t.Fatal("expected stale created to fail verification")
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

	result := futureVerifier.VerifyRequest(req, body, func(keyID string) (ed25519.PublicKey, error) {
		return km.GetSigningKey().PublicKey, nil
	})
	if result.Verified {
		t.Fatal("expected future created to fail verification")
	}
	if result.Error == nil || !strings.Contains(result.Error.Error(), "too far in the future") {
		t.Fatalf("error = %v, want future created rejection", result.Error)
	}
}

func TestRFC9421_VerifyRejectsHMAC(t *testing.T) {
	verifier := crypto.NewRFC9421Verifier()
	now := time.Now().Unix()
	req := httptest.NewRequest("POST", "https://example.com/test", nil)
	req.Header.Set("Signature-Input", fmt.Sprintf(
		`ocm=("@method" "@target-uri" "content-digest" "content-length" "date");created=%d;keyid="example.com#key1";alg="hmac-sha256"`,
		now,
	))
	req.Header.Set("Signature", "ocm=:AAAA:")

	result := verifier.VerifyRequest(req, nil, func(keyID string) (ed25519.PublicKey, error) {
		return nil, fmt.Errorf("should not fetch key")
	})
	if result.Verified {
		t.Fatal("expected symmetric algorithm rejection")
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

	keyFetcher := func(keyID string) (ed25519.PublicKey, error) {
		return km.GetSigningKey().PublicKey, nil
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
		fetcher        func(string) (ed25519.PublicKey, error)
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
		AllowedAlgorithms:     []string{"ed25519"},
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
	if len(opts.AllowedAlgorithms) != 1 || opts.AllowedAlgorithms[0] != "ed25519" {
		t.Fatalf("AllowedAlgorithms = %v", opts.AllowedAlgorithms)
	}
}
