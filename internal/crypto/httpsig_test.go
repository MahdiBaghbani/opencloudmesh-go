package crypto_test

import (
	"bytes"
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/crypto"
)

func TestRFC9421_SignAndVerify(t *testing.T) {
	km := crypto.NewKeyManager("", "https://example.com")
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatalf("LoadOrGenerate failed: %v", err)
	}

	signer := crypto.NewRFC9421Signer(km)
	verifier := crypto.NewRFC9421Verifier()

	body := []byte(`{"test": "data"}`)

	req, err := http.NewRequest("POST", "https://example.com/ocm/shares", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}
	req.Host = "example.com"
	req.Header.Set("Content-Type", "application/json")

	// Sign the request
	if err := signer.SignRequest(req, body); err != nil {
		t.Fatalf("SignRequest failed: %v", err)
	}

	// Check that signature headers were added
	if req.Header.Get("Signature-Input") == "" {
		t.Error("missing Signature-Input header")
	}
	if req.Header.Get("Signature") == "" {
		t.Error("missing Signature header")
	}

	// Verify the signature
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

	signer := crypto.NewRFC9421Signer(km)
	body := []byte(`{"test": "data"}`)

	req, _ := http.NewRequest("POST", "https://example.com/ocm/shares", bytes.NewReader(body))
	req.Host = "example.com"
	req.Header.Set("Content-Type", "application/json")

	if err := signer.SignRequest(req, body); err != nil {
		t.Fatalf("SignRequest failed: %v", err)
	}

	sigInput := req.Header.Get("Signature-Input")

	// Check that required components are in the signature params
	if !strings.Contains(sigInput, "\"@method\"") {
		t.Error("@method not in signature params")
	}
	if !strings.Contains(sigInput, "\"@target-uri\"") {
		t.Error("@target-uri not in signature params")
	}
	if !strings.Contains(sigInput, "created=") {
		t.Error("created not in signature params")
	}
	if !strings.Contains(sigInput, "keyid=") {
		t.Error("keyid not in signature params")
	}
	if !strings.Contains(sigInput, "alg=\"ed25519\"") {
		t.Error("alg not in signature params")
	}
}

func TestRFC9421_VerifyMissingHeaders(t *testing.T) {
	verifier := crypto.NewRFC9421Verifier()

	req := httptest.NewRequest("POST", "https://example.com/ocm/shares", nil)

	// No signature headers - should not verify
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
	// Create two different key managers
	km1 := crypto.NewKeyManager("", "https://example.com")
	km2 := crypto.NewKeyManager("", "https://attacker.com")
	km1.LoadOrGenerate()
	km2.LoadOrGenerate()

	signer := crypto.NewRFC9421Signer(km1)
	verifier := crypto.NewRFC9421Verifier()

	body := []byte(`{"test": "data"}`)
	req, _ := http.NewRequest("POST", "https://example.com/ocm/shares", bytes.NewReader(body))
	req.Host = "example.com"
	req.Header.Set("Content-Type", "application/json")

	// Sign with km1
	signer.SignRequest(req, body)

	// Try to verify with km2's public key - should fail
	result := verifier.VerifyRequest(req, body, func(keyID string) (ed25519.PublicKey, error) {
		return km2.GetSigningKey().PublicKey, nil
	})

	if result.Verified {
		t.Error("verification should fail with wrong key")
	}
}

func TestContentDigest(t *testing.T) {
	body := []byte(`{"test": "data"}`)

	req := httptest.NewRequest("POST", "/test", bytes.NewReader(body))

	// Without Content-Digest header, verification should pass
	if err := crypto.VerifyContentDigest(req, body); err != nil {
		t.Errorf("should pass without Content-Digest: %v", err)
	}

	// Sign with correct digest
	km := crypto.NewKeyManager("", "https://example.com")
	km.LoadOrGenerate()
	signer := crypto.NewRFC9421Signer(km)

	req2, _ := http.NewRequest("POST", "https://example.com/test", bytes.NewReader(body))
	req2.Host = "example.com"
	signer.SignRequest(req2, body)

	// Verify with correct body
	if err := crypto.VerifyContentDigest(req2, body); err != nil {
		t.Errorf("verification should pass with correct body: %v", err)
	}

	// Verify with wrong body
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
