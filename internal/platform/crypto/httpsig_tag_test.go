package crypto_test

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigalg"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigparams"
)

func TestVerifyRequest_AcceptsForeignLabelsWithOneOCM(t *testing.T) {
	km := mustHTTPSigKeyManager(t)
	opts := httpsigFixedOptions()
	signer := crypto.NewRFC9421SignerWithOptions(km, opts)
	verifier := crypto.NewRFC9421VerifierWithOptions(opts)

	body := httpsigTestBodyJSON

	req, err := http.NewRequest(http.MethodPost, "https://example.com/ocm/shares", bytes.NewReader(body))
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

	result := verifier.VerifyRequest(req, body, httpsigEd25519KeyFetcher(km))
	if !result.Verified {
		t.Fatalf("expected verification of the ocm member alongside an ignored foreign label, got verified=false reason=%s err=%v", result.Reason, result.Error)
	}

	if result.KeyID != km.GetKeyID() {
		t.Errorf("KeyID = %q, want %q", result.KeyID, km.GetKeyID())
	}
}

func TestVerifyRequest_RejectsDuplicateSignatureLabels(t *testing.T) {
	verifier := crypto.NewRFC9421Verifier()
	now := time.Now().Unix()
	body := httpsigTestBodyJSON
	digest := httpsigContentDigestHeader(body)

	newReq := func(sigInput, signature string) *http.Request {
		req := httptest.NewRequest(http.MethodPost, "https://example.com/ocm/shares", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Content-Digest", digest)
		req.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
		req.Header.Set("Date", httpsigStandardDate)
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
			httpsigPlaceholderSig,
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

func TestVerifyRequest_RejectsDuplicateOCM(t *testing.T) {
	verifier := crypto.NewRFC9421Verifier()
	now := time.Now().Unix()
	body := httpsigTestBodyJSON
	digest := httpsigContentDigestHeader(body)

	req := httptest.NewRequest(http.MethodPost, "https://example.com/ocm/shares", bytes.NewReader(body))
	req.Header.Set("Content-Digest", digest)
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
	req.Header.Set("Date", httpsigStandardDate)
	req.Header.Set("Signature-Input", fmt.Sprintf(
		`ocm=("@method" "@target-uri" "content-digest" "content-length" "date");created=%d;keyid="a#1";alg="ed25519";tag="ocm", ocm=("@method" "@target-uri" "content-digest" "content-length" "date");created=%d;keyid="b#1";alg="ed25519";tag="ocm"`,
		now, now,
	))
	req.Header.Set("Signature", httpsigPlaceholderSig)

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
	req := httptest.NewRequest(http.MethodPost, "https://example.com/ocm/shares", nil)
	req.Header.Set("Date", httpsigStandardDate)
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

func TestHTTPSig_Sign_AlwaysEmitsTag(t *testing.T) {
	km := mustHTTPSigKeyManager(t)

	opts := httpsigFixedOptions()

	signer := crypto.NewRFC9421SignerWithOptions(km, opts)

	body := httpsigTestBodyJSON

	req, err := http.NewRequest(http.MethodPost, "https://example.com/ocm/shares", bytes.NewReader(body))
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

	result := verifier.VerifyRequest(req, body, httpsigEd25519KeyFetcher(km))
	if !result.Verified {
		t.Fatalf("verification of signed request with tag failed: %v", result.Error)
	}
}

func TestHTTPSig_Sign_AlwaysEmitsTagWithCustomLabel(t *testing.T) {
	km := mustHTTPSigKeyManager(t)

	opts := httpsigFixedOptions()
	opts.Label = "customlabel"

	signer := crypto.NewRFC9421SignerWithOptions(km, opts)

	body := httpsigTestBodyJSON

	req, err := http.NewRequest(http.MethodPost, "https://example.com/ocm/shares", bytes.NewReader(body))
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

	result := verifier.VerifyRequest(req, body, httpsigEd25519KeyFetcher(km))
	if !result.Verified {
		t.Fatalf("verification of signed request with custom label failed: %v", result.Error)
	}
}

func TestHTTPSig_Verify_ByTag_IgnoresLabel(t *testing.T) {
	km := mustHTTPSigKeyManager(t)

	signOpts := crypto.DefaultRFC9421Options()
	signOpts.Now = func() time.Time { return httpsigFixedNow() }
	signOpts.Label = "not-ocm"

	signer := crypto.NewRFC9421SignerWithOptions(km, signOpts)
	verifyOpts := crypto.DefaultRFC9421Options()
	verifyOpts.Now = signOpts.Now
	verifier := crypto.NewRFC9421VerifierWithOptions(verifyOpts)

	body := httpsigTestBodyJSON

	req, err := http.NewRequest(http.MethodPost, "https://example.com/ocm/shares", bytes.NewReader(body))
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

	result := verifier.VerifyRequest(req, body, httpsigEd25519KeyFetcher(km))
	if !result.Verified {
		t.Fatalf("expected verification by tag to ignore label, got verified=false reason=%s err=%v", result.Reason, result.Error)
	}

	if result.KeyID != km.GetKeyID() {
		t.Errorf("KeyID = %q, want %q", result.KeyID, km.GetKeyID())
	}
}

func TestHTTPSig_Verify_TagCount(t *testing.T) {
	opts := httpsigFixedOptions()
	verifier := crypto.NewRFC9421VerifierWithOptions(opts)

	body := httpsigTestBodyJSON
	digest := httpsigContentDigestHeader(body)
	newReq := func(sigInput string) *http.Request {
		req := httptest.NewRequest(http.MethodPost, "https://example.com/ocm/shares", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Content-Digest", digest)
		req.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
		req.Header.Set("Date", httpsigStandardDate)
		req.Header.Set("Signature-Input", sigInput)
		req.Header.Set("Signature", httpsigPlaceholderSig)

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
	km := mustHTTPSigKeyManager(t)

	opts := httpsigFixedOptions()
	opts.Label = "integritylabel"
	signer := crypto.NewRFC9421SignerWithOptions(km, opts)
	verifier := crypto.NewRFC9421VerifierWithOptions(opts)

	body := httpsigTestBodyJSON

	req, err := http.NewRequest(http.MethodPost, "https://example.com/ocm/shares", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}

	req.Host = "example.com"

	if err := signer.SignRequest(req, body); err != nil { //nolint:govet // shadow: sequential err in table-driven test is benign
		t.Fatalf("SignRequest failed: %v", err)
	}

	sigInput := req.Header.Get("Signature-Input")
	if !strings.HasPrefix(sigInput, "integritylabel=") {
		t.Fatalf("Signature-Input = %q, want integritylabel= prefix", sigInput)
	}

	if !strings.Contains(sigInput, `;tag="ocm"`) {
		t.Fatalf("Signature-Input must include tag parameter: %q", sigInput)
	}

	result := verifier.VerifyRequest(req, body, httpsigEd25519KeyFetcher(km))
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
