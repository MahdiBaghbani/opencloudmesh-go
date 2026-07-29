package crypto_test

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigalg"
)

func TestRFC9421_VerifyMissingHeaders(t *testing.T) {
	verifier := crypto.NewRFC9421Verifier()

	req := httptest.NewRequest(http.MethodPost, "https://example.com/ocm/shares", nil)

	if verifier.HasSignatureHeaders(req) {
		t.Error("should not have signature headers")
	}

	result := verifier.VerifyRequest(req, nil, func(_ string) (sigalg.ResolvedPublicKey, error) {
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

	if err := km1.LoadOrGenerate(); err != nil {
		t.Fatalf("LoadOrGenerate km1: %v", err)
	}

	if err := km2.LoadOrGenerate(); err != nil {
		t.Fatalf("LoadOrGenerate km2: %v", err)
	}

	opts := httpsigFixedOptions()

	signer := crypto.NewRFC9421SignerWithOptions(km1, opts)
	verifier := crypto.NewRFC9421VerifierWithOptions(opts)

	body := []byte(`{"test": "data"}`)

	req, err := http.NewRequest(http.MethodPost, "https://example.com/ocm/shares", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("call failed: %v", err)
	}

	req.Host = "example.com"
	req.Header.Set("Content-Type", "application/json")

	if err := signer.SignRequest(req, body); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}

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

func TestRFC9421_VerifyTamperedKeyIDRejected(t *testing.T) {
	km := mustHTTPSigKeyManager(t)
	opts := httpsigFixedOptions()
	signer := crypto.NewRFC9421SignerWithOptions(km, opts)
	verifier := crypto.NewRFC9421VerifierWithOptions(opts)

	body := []byte(`{"test": "data"}`)

	req, err := http.NewRequest(http.MethodPost, "https://example.com/ocm/shares", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("call failed: %v", err)
	}

	req.Host = "example.com"
	req.Header.Set("Content-Type", "application/json")

	if err := signer.SignRequest(req, body); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}

	// An in-transit keyid swap resolves nothing: no set kid equals the
	// tampered keyid, so verification fails at key resolution with the
	// distinct key_not_found reason rather than a generic error.
	tampered := strings.Replace(
		req.Header.Get("Signature-Input"),
		fmt.Sprintf(`keyid=%q`, km.GetKeyID()),
		`keyid="example.com#key2"`,
		1,
	)
	if tampered == req.Header.Get("Signature-Input") {
		t.Fatal("keyid replacement did not apply")
	}

	req.Header.Set("Signature-Input", tampered)

	result := verifier.VerifyRequest(req, body, func(keyID string) (sigalg.ResolvedPublicKey, error) {
		return km.JWKS().ResolveExactKeyID(keyID)
	})
	if result.Verified {
		t.Fatal("expected tampered keyid rejection")
	}

	if result.Reason != crypto.ReasonKeyNotFound {
		t.Fatalf("Reason = %q, want %q (err=%v)", result.Reason, crypto.ReasonKeyNotFound, result.Error)
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
			req := httptest.NewRequest(http.MethodPost, "/test", nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			if verifier.HasSignatureHeaders(req) != tt.expected {
				t.Errorf("HasSignatureHeaders = %v, want %v", !tt.expected, tt.expected)
			}
		})
	}
}
