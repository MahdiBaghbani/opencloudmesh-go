package crypto_test

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigalg"
)

func TestRFC9421_VerifyRejectsHMAC(t *testing.T) {
	verifier := crypto.NewRFC9421Verifier()
	now := time.Now().Unix()
	req := httptest.NewRequest(http.MethodPost, "https://example.com/test", nil)
	req.Header.Set("Date", httpsigStandardDate)

	emptyDigest := base64.StdEncoding.EncodeToString(sigalg.SumSHA256(nil))
	req.Header.Set("Content-Digest", "sha-256=:"+emptyDigest+":")
	req.Header.Set("Content-Length", "0")
	req.Header.Set("Signature-Input", fmt.Sprintf(
		`ocm=("@method" "@target-uri" "content-digest" "content-length" "date");created=%d;keyid="example.com#key1";alg="hmac-sha256";tag="ocm"`,
		now,
	))
	req.Header.Set("Signature", httpsigPlaceholderSigAlt)

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

func TestVerifyRequest_RejectPaths(t *testing.T) {
	verifier := crypto.NewRFC9421Verifier()

	km := mustHTTPSigKeyManager(t)

	zeroSig := "ocm=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==:"

	keyFetcher := httpsigEd25519KeyFetcher(km)

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
			req := httptest.NewRequest(http.MethodPost, "https://example.com/test", nil)
			req.Header.Set("Date", httpsigStandardDate)

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

func TestVerifyRequest_DoesNotFetchBeforeCreatedCheck(t *testing.T) {
	verifier := crypto.NewRFC9421Verifier()
	fetches := 0
	req := httptest.NewRequest(http.MethodPost, "https://example.com/ocm/shares", nil)
	req.Header.Set("Date", httpsigStandardDate)
	req.Header.Set("Signature-Input", `ocm=("@method" "@target-uri" "content-digest" "content-length" "date");keyid="example.com#key1";alg="ed25519";tag="ocm"`)
	req.Header.Set("Signature", httpsigPlaceholderSigAlt)

	result := verifier.VerifyRequest(req, nil, func(_ string) (sigalg.ResolvedPublicKey, error) {
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
	req := httptest.NewRequest(http.MethodPost, "https://example.com/ocm/shares", nil)
	req.Header.Set("Date", httpsigStandardDate)
	req.Header.Set("Signature-Input", fmt.Sprintf(
		`ocm=("@method" "@target-uri");created=%d;keyid="example.com#key1";alg="ed25519";tag="ocm"`,
		now,
	))
	req.Header.Set("Signature", httpsigPlaceholderSigAlt)

	result := verifier.VerifyRequest(req, nil, func(_ string) (sigalg.ResolvedPublicKey, error) {
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
	req := httptest.NewRequest(http.MethodPost, "https://example.com/ocm/shares", nil)
	req.Header.Set("Date", httpsigStandardDate)
	req.Header.Set("Content-Digest", "sha-256=:AAAA:")
	req.Header.Set("Content-Length", "2")
	req.Header.Set("Signature-Input", fmt.Sprintf(
		`ocm=("@method" "@target-uri" "content-digest" "content-length" "date");created=%d;keyid="example.com#key1";alg="ed25519";tag="ocm"`,
		now,
	))
	req.Header.Set("Signature", "ocm=not-a-byte-sequence")

	result := verifier.VerifyRequest(req, []byte("{}"), func(_ string) (sigalg.ResolvedPublicKey, error) {
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
