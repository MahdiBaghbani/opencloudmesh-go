package crypto_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigalg"
)

func TestRFC9421_VerifyRejectsStaleCreated(t *testing.T) {
	km := mustHTTPSigKeyManager(t)

	now := httpsigFixedNow()
	opts := crypto.DefaultRFC9421Options()
	opts.Now = func() time.Time { return now }
	opts.CreatedMaxAge = time.Minute

	signer := crypto.NewRFC9421SignerWithOptions(km, opts)

	body := []byte(`{"test": "data"}`)
	req, _ := http.NewRequest(http.MethodPost, "https://example.com/ocm/shares", bytes.NewReader(body))
	req.Host = "example.com"

	if err := signer.SignRequest(req, body); err != nil {
		t.Fatal(err)
	}

	staleVerifier := httpsigVerifierWithNow(opts, now.Add(2*time.Minute))

	result := staleVerifier.VerifyRequest(req, body, httpsigEd25519KeyFetcher(km))
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
	km := mustHTTPSigKeyManager(t)

	signTime := httpsigFixedNow()
	verifyTime := signTime.Add(-2 * time.Minute)

	opts := crypto.DefaultRFC9421Options()
	opts.Now = func() time.Time { return signTime }
	opts.CreatedMaxSkew = time.Minute

	signer := crypto.NewRFC9421SignerWithOptions(km, opts)

	body := []byte(`{"test": "data"}`)

	req, err := http.NewRequest(http.MethodPost, "https://example.com/ocm/shares", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}

	req.Host = "example.com"

	if err := signer.SignRequest(req, body); err != nil {
		t.Fatal(err)
	}

	futureVerifier := httpsigVerifierWithNow(opts, verifyTime)

	result := futureVerifier.VerifyRequest(req, body, httpsigEd25519KeyFetcher(km))
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

func TestRFC9421_VerifyCreatedBoundaryAtMaxSkew(t *testing.T) {
	km := mustHTTPSigKeyManager(t)

	signTime := httpsigFixedNow()
	maxSkew := 60 * time.Second
	opts := crypto.DefaultRFC9421Options()
	opts.Now = func() time.Time { return signTime }
	opts.CreatedMaxSkew = maxSkew

	signer := crypto.NewRFC9421SignerWithOptions(km, opts)
	body := httpsigTestBodyJSON
	req, _ := http.NewRequest(http.MethodPost, "https://example.com/ocm/shares", bytes.NewReader(body))

	req.Host = "example.com"
	if err := signer.SignRequest(req, body); err != nil {
		t.Fatal(err)
	}

	atSkewVerifier := httpsigVerifierWithNow(crypto.RFC9421Options{Label: opts.Label, CreatedMaxAge: opts.CreatedMaxAge, CreatedMaxSkew: maxSkew, AllowedAlgorithms: opts.AllowedAlgorithms, RequiredComponents: opts.RequiredComponents}, signTime.Add(-maxSkew))

	result := atSkewVerifier.VerifyRequest(req, body, httpsigEd25519KeyFetcher(km))
	if !result.Verified {
		t.Fatalf("created at max skew should verify: %v", result.Error)
	}

	pastSkewVerifier := httpsigVerifierWithNow(crypto.RFC9421Options{Label: opts.Label, CreatedMaxAge: opts.CreatedMaxAge, CreatedMaxSkew: maxSkew, AllowedAlgorithms: opts.AllowedAlgorithms, RequiredComponents: opts.RequiredComponents}, signTime.Add(-maxSkew-time.Second))

	result = pastSkewVerifier.VerifyRequest(req, body, httpsigEd25519KeyFetcher(km))
	if result.Verified {
		t.Fatal("created past max skew should fail")
	}

	if result.Reason != crypto.ReasonFutureCreated {
		t.Fatalf("Reason=%q want future_created", result.Reason)
	}
}

func TestRFC9421_VerifyCreatedBoundaryAtMaxAge(t *testing.T) {
	km := mustHTTPSigKeyManager(t)

	signTime := httpsigFixedNow()
	maxAge := time.Minute
	opts := crypto.DefaultRFC9421Options()
	opts.Now = func() time.Time { return signTime }
	opts.CreatedMaxAge = maxAge

	signer := crypto.NewRFC9421SignerWithOptions(km, opts)
	body := httpsigTestBodyJSON
	req, _ := http.NewRequest(http.MethodPost, "https://example.com/ocm/shares", bytes.NewReader(body))

	req.Host = "example.com"
	if err := signer.SignRequest(req, body); err != nil {
		t.Fatal(err)
	}

	atAgeVerifier := httpsigVerifierWithNow(crypto.RFC9421Options{Label: opts.Label, CreatedMaxAge: maxAge, CreatedMaxSkew: opts.CreatedMaxSkew, AllowedAlgorithms: opts.AllowedAlgorithms, RequiredComponents: opts.RequiredComponents}, signTime.Add(maxAge))

	result := atAgeVerifier.VerifyRequest(req, body, httpsigEd25519KeyFetcher(km))
	if !result.Verified {
		t.Fatalf("created at max age should verify: %v", result.Error)
	}

	staleVerifier := httpsigVerifierWithNow(crypto.RFC9421Options{Label: opts.Label, CreatedMaxAge: maxAge, CreatedMaxSkew: opts.CreatedMaxSkew, AllowedAlgorithms: opts.AllowedAlgorithms, RequiredComponents: opts.RequiredComponents}, signTime.Add(maxAge+time.Second))

	result = staleVerifier.VerifyRequest(req, body, httpsigEd25519KeyFetcher(km))
	if result.Verified {
		t.Fatal("created past max age should fail")
	}

	if result.Reason != crypto.ReasonStaleCreated {
		t.Fatalf("Reason=%q want stale_created", result.Reason)
	}
}

func TestVerifyRequest_RejectsFutureCreated(t *testing.T) {
	km := mustHTTPSigKeyManager(t)
	signTime := httpsigFixedNow()
	verifyTime := signTime.Add(-2 * time.Minute)

	opts := crypto.DefaultRFC9421Options()
	opts.Now = func() time.Time { return signTime }
	opts.CreatedMaxSkew = time.Minute
	signer := crypto.NewRFC9421SignerWithOptions(km, opts)

	body := httpsigTestBodyJSON

	req, err := http.NewRequest(http.MethodPost, "https://example.com/ocm/shares", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}

	req.Host = "example.com"
	if err := signer.SignRequest(req, body); err != nil {
		t.Fatal(err)
	}

	verifier := httpsigVerifierWithNow(opts, verifyTime)

	result := verifier.VerifyRequest(req, body, httpsigEd25519KeyFetcher(km))
	if result.Verified {
		t.Fatal("expected future created to fail verification")
	}

	if result.Reason != crypto.ReasonFutureCreated {
		t.Fatalf("Reason = %q, want %q", result.Reason, crypto.ReasonFutureCreated)
	}
}

func TestVerifyRequest_RejectsStaleCreated(t *testing.T) {
	km := mustHTTPSigKeyManager(t)
	now := httpsigFixedNow()
	opts := crypto.DefaultRFC9421Options()
	opts.Now = func() time.Time { return now }
	opts.CreatedMaxAge = time.Minute
	signer := crypto.NewRFC9421SignerWithOptions(km, opts)

	body := httpsigTestBodyJSON

	req, err := http.NewRequest(http.MethodPost, "https://example.com/ocm/shares", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}

	req.Host = "example.com"
	if err := signer.SignRequest(req, body); err != nil {
		t.Fatal(err)
	}

	verifier := httpsigVerifierWithNow(opts, now.Add(2*time.Minute))

	result := verifier.VerifyRequest(req, body, httpsigEd25519KeyFetcher(km))
	if result.Verified {
		t.Fatal("expected stale created to fail verification")
	}

	if result.Reason != crypto.ReasonStaleCreated {
		t.Fatalf("Reason = %q, want %q", result.Reason, crypto.ReasonStaleCreated)
	}
}

func TestVerifyRequest_RejectsMissingCreated(t *testing.T) {
	verifier := crypto.NewRFC9421Verifier()
	req := httptest.NewRequest(http.MethodPost, "https://example.com/ocm/shares", nil)
	req.Header.Set("Date", httpsigStandardDate)
	req.Header.Set("Signature-Input", `ocm=("@method" "@target-uri" "date");keyid="a#1";alg="ed25519";tag="ocm"`)
	req.Header.Set("Signature", httpsigPlaceholderSigAlt)

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
