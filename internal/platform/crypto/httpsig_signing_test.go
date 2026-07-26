package crypto_test

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigalg"
)

func TestRFC9421_SignAndVerify_EmptyBody(t *testing.T) {
	km := mustHTTPSigKeyManager(t)

	opts := httpsigFixedOptions()

	signer := crypto.NewRFC9421SignerWithOptions(km, opts)
	verifier := crypto.NewRFC9421VerifierWithOptions(opts)

	req, err := http.NewRequest(http.MethodGet, "https://example.com/ocm/discovery", nil)
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

	result := verifier.VerifyRequest(req, nil, httpsigEd25519KeyFetcher(km))
	if !result.Verified {
		t.Fatalf("empty-body verification failed: %v", result.Error)
	}
}

func TestRFC9421_SignAndVerify(t *testing.T) {
	km := mustHTTPSigKeyManager(t)

	opts := httpsigFixedOptions()

	signer := crypto.NewRFC9421SignerWithOptions(km, opts)
	verifier := crypto.NewRFC9421VerifierWithOptions(opts)

	body := []byte(`{"test": "data"}`)

	req, err := http.NewRequest(http.MethodPost, "https://example.com/ocm/shares", bytes.NewReader(body))
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

	result := verifier.VerifyRequest(req, body, httpsigEd25519KeyFetcher(km))

	if !result.Verified {
		t.Errorf("verification failed: %v", result.Error)
	}

	if result.KeyID != km.GetKeyID() {
		t.Errorf("expected keyId %q, got %q", km.GetKeyID(), result.KeyID)
	}
}

func TestRFC9421_SignatureParams(t *testing.T) {
	km := mustHTTPSigKeyManager(t)

	opts := httpsigFixedOptions()
	signer := crypto.NewRFC9421SignerWithOptions(km, opts)

	body := []byte(`{"test": "data"}`)
	req, _ := http.NewRequest(http.MethodPost, "https://example.com/ocm/shares", bytes.NewReader(body))
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

func TestHTTPSig_GoldenDefaultSignatureInput(t *testing.T) {
	km := mustHTTPSigKeyManager(t)

	opts := httpsigFixedOptions()
	signer := crypto.NewRFC9421SignerWithOptions(km, opts)

	body := httpsigTestBodyJSON

	req, err := http.NewRequest(http.MethodPost, "https://example.com/ocm/shares", bytes.NewReader(body))
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
