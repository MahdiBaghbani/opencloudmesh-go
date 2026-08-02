// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

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

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://example.com/ocm/discovery", nil)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}

	req.Host = "example.com"

	if err := signer.SignRequest(req, nil); err != nil {
		t.Fatalf("SignRequest failed: %v", err)
	}

	sigInput := req.Header.Get("Signature-Input")
	for _, want := range []string{`"@method"`, `"@target-uri"`, `"content-digest"`, `"content-length"`} {
		if !strings.Contains(sigInput, want) {
			t.Fatalf("empty-body Signature-Input missing %s: %q", want, sigInput)
		}
	}

	if strings.Contains(sigInput, `"date"`) {
		t.Fatalf("empty-body Signature-Input must be date-free: %q", sigInput)
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

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://example.com/ocm/shares", bytes.NewReader(body))
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

	if req.Header.Get("Date") != "" {
		t.Errorf("signing must not create a Date header, got %q", req.Header.Get("Date"))
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

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://example.com/ocm/shares", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("call failed: %v", err)
	}

	req.Host = "example.com"
	req.Header.Set("Content-Type", "application/json")

	if err := signer.SignRequest(req, body); err != nil {
		t.Fatalf("SignRequest failed: %v", err)
	}

	sigInput := req.Header.Get("Signature-Input")
	for _, want := range []string{`"@method"`, `"@target-uri"`, `"content-digest"`, `"content-length"`, "created=", "keyid=", `alg="ed25519"`} {
		if !strings.Contains(sigInput, want) {
			t.Errorf("Signature-Input missing %q: %q", want, sigInput)
		}
	}

	if strings.Contains(sigInput, `"date"`) {
		t.Errorf("Signature-Input must be date-free: %q", sigInput)
	}
}

func TestHTTPSig_GoldenDefaultSignatureInput(t *testing.T) {
	km := mustHTTPSigKeyManager(t)

	opts := httpsigFixedOptions()
	signer := crypto.NewRFC9421SignerWithOptions(km, opts)

	body := httpsigTestBodyJSON

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://example.com/ocm/shares", bytes.NewReader(body))
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
		`^ocm=\("@method" "@target-uri" "content-digest" "content-length"\);created=1730815200;keyid="[^"]+";alg="ed25519";tag="ocm"$`,
	)
	if !goldenRe.MatchString(sigInput) {
		t.Fatalf("Signature-Input = %q, does not match golden default pattern", sigInput)
	}
}

func TestSignRequest_DefaultSigningDoesNotCreateDate(t *testing.T) {
	km := mustHTTPSigKeyManager(t)
	signer := crypto.NewRFC9421SignerWithOptions(km, httpsigFixedOptions())

	body := httpsigTestBodyJSON

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://example.com/ocm/shares", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}

	req.Host = "example.com"

	if err := signer.SignRequest(req, body); err != nil {
		t.Fatalf("SignRequest failed: %v", err)
	}

	if got := req.Header.Get("Date"); got != "" {
		t.Fatalf("default signing must not create a Date header, got %q", got)
	}

	sigInput := req.Header.Get("Signature-Input")
	if strings.Contains(sigInput, `"date"`) {
		t.Fatalf("default Signature-Input must be date-free: %q", sigInput)
	}
}

func TestSignRequest_PreexistingDateRemainsUnsigned(t *testing.T) {
	km := mustHTTPSigKeyManager(t)
	opts := httpsigFixedOptions()
	signer := crypto.NewRFC9421SignerWithOptions(km, opts)
	verifier := crypto.NewRFC9421VerifierWithOptions(opts)

	body := httpsigTestBodyJSON

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://example.com/ocm/shares", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}

	req.Host = "example.com"
	req.Header.Set("Date", httpsigStandardDate)

	if err := signer.SignRequest(req, body); err != nil {
		t.Fatalf("SignRequest failed: %v", err)
	}

	if got := req.Header.Get("Date"); got != httpsigStandardDate {
		t.Fatalf("preexisting Date header must be preserved, got %q", got)
	}

	sigInput := req.Header.Get("Signature-Input")
	if strings.Contains(sigInput, `"date"`) {
		t.Fatalf("preexisting Date must stay out of Signature-Input: %q", sigInput)
	}

	result := verifier.VerifyRequest(req, body, httpsigEd25519KeyFetcher(km))
	if !result.Verified {
		t.Fatalf("verification failed with preexisting unsigned Date: %v", result.Error)
	}
}

func TestSignRequest_ExplicitDateComponentCovered(t *testing.T) {
	tests := []struct {
		name            string
		preexistingDate bool
	}{
		{name: "without preexisting Date", preexistingDate: false},
		{name: "with preexisting Date", preexistingDate: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			km := mustHTTPSigKeyManager(t)
			opts := httpsigFixedOptions()
			opts.RequiredComponents = []string{"@method", "@target-uri", "content-digest", "content-length", "date"}
			signer := crypto.NewRFC9421SignerWithOptions(km, opts)

			body := httpsigTestBodyJSON

			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://example.com/ocm/shares", bytes.NewReader(body))
			if err != nil {
				t.Fatalf("NewRequest failed: %v", err)
			}

			req.Host = "example.com"
			if tc.preexistingDate {
				req.Header.Set("Date", httpsigStandardDate)
			}

			if err := signer.SignRequest(req, body); err != nil {
				t.Fatalf("SignRequest with explicit date component failed: %v", err)
			}

			if got := req.Header.Get("Date"); got == "" {
				t.Fatal("explicit date component requires a Date header to cover")
			}

			if tc.preexistingDate {
				if got := req.Header.Get("Date"); got != httpsigStandardDate {
					t.Fatalf("preexisting Date header must be preserved, got %q", got)
				}
			}

			sigInput := req.Header.Get("Signature-Input")
			if !strings.Contains(sigInput, `"date"`) {
				t.Fatalf("explicit date component must be covered: %q", sigInput)
			}

			verifyOpts := httpsigFixedOptions()
			verifyOpts.RequiredComponents = opts.RequiredComponents
			explicitVerifier := crypto.NewRFC9421VerifierWithOptions(verifyOpts)

			result := explicitVerifier.VerifyRequest(req, body, httpsigEd25519KeyFetcher(km))
			if !result.Verified {
				t.Fatalf("explicit-date verification failed: %v", result.Error)
			}

			// The OCM minimum is an at-least set: the default date-free
			// verifier also accepts the extra covered date component.
			defaultVerifier := crypto.NewRFC9421VerifierWithOptions(httpsigFixedOptions())

			defaultResult := defaultVerifier.VerifyRequest(req, body, httpsigEd25519KeyFetcher(km))
			if !defaultResult.Verified {
				t.Fatalf("default verifier must accept extra covered date: %v", defaultResult.Error)
			}
		})
	}
}
