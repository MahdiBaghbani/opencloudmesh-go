package crypto_test

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigalg"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

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
	body := httpsigTestBodyJSON
	sha256Val := base64.StdEncoding.EncodeToString(sigalg.SumSHA256(body))
	sha512Val := base64.StdEncoding.EncodeToString(sigalg.SumSHA512(body))

	req := httptest.NewRequest("POST", "/test", bytes.NewReader(body))
	req.Header.Set("Content-Digest", fmt.Sprintf("sha-256=:%s:, sha-512=:%s:", sha256Val, sha512Val))

	if err := crypto.VerifyContentDigest(req, body); err != nil {
		t.Fatalf("multi-digest verify failed: %v", err)
	}
}

func TestVerifyContentDigest_MultiDigest_OneTampered(t *testing.T) {
	body := httpsigTestBodyJSON
	sha256Val := base64.StdEncoding.EncodeToString(sigalg.SumSHA256(body))
	tampered := base64.StdEncoding.EncodeToString(sigalg.SumSHA512([]byte("wrong")))

	req := httptest.NewRequest("POST", "/test", bytes.NewReader(body))
	req.Header.Set("Content-Digest", fmt.Sprintf("sha-256=:%s:, sha-512=:%s:", sha256Val, tampered))

	if err := crypto.VerifyContentDigest(req, body); err == nil {
		t.Fatal("expected failure when one recognized digest is tampered")
	}
}

func TestVerifyContentDigest_UnknownPlusRecognizedRejected(t *testing.T) {
	body := httpsigTestBodyJSON
	sha256Val := base64.StdEncoding.EncodeToString(sigalg.SumSHA256(body))

	req := httptest.NewRequest("POST", "/test", bytes.NewReader(body))
	req.Header.Set("Content-Digest", fmt.Sprintf("sha-256=:%s:, foo=:%s:", sha256Val, sha256Val))

	if err := crypto.VerifyContentDigest(req, body); err == nil {
		t.Fatal("expected rejection when an unrecognized digest algorithm is listed")
	}
}

func TestVerifyContentDigest_OnlyUnknownAlgorithmsRejected(t *testing.T) {
	body := httpsigTestBodyJSON
	val := base64.StdEncoding.EncodeToString(sigalg.SumSHA256(body))

	req := httptest.NewRequest("POST", "/test", bytes.NewReader(body))
	req.Header.Set("Content-Digest", fmt.Sprintf("foo=:%s:, bar=:%s:", val, val))

	if err := crypto.VerifyContentDigest(req, body); err == nil {
		t.Fatal("expected rejection when no recognized digest is present")
	}
}

func TestVerifyRequest_RejectsMissingContentDigestHeaderOnNonEmptyBody(t *testing.T) {
	km := mustHTTPSigKeyManager(t)
	opts := httpsigFixedOptions()
	signer := crypto.NewRFC9421SignerWithOptions(km, opts)
	verifier := crypto.NewRFC9421VerifierWithOptions(opts)

	body := httpsigTestBodyJSON
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
	km := mustHTTPSigKeyManager(t)
	opts := httpsigFixedOptions()
	signer := crypto.NewRFC9421SignerWithOptions(km, opts)
	verifier := crypto.NewRFC9421VerifierWithOptions(opts)

	body := httpsigTestBodyJSON
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
	body := httpsigTestBodyJSON

	req := httptest.NewRequest("POST", "https://example.com/ocm/shares", bytes.NewReader(body))
	req.Header.Set("Date", httpsigStandardDate)
	req.Header.Set("Signature-Input", fmt.Sprintf(
		`ocm=("@method" "@target-uri" "date");created=%d;keyid="example.com#key1";alg="ed25519";tag="ocm"`,
		now,
	))
	req.Header.Set("Signature", httpsigPlaceholderSigAlt)

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
	km := mustHTTPSigKeyManager(t)
	opts := httpsigFixedOptions()
	signer := crypto.NewRFC9421SignerWithOptions(km, opts)
	verifier := crypto.NewRFC9421VerifierWithOptions(opts)

	body := httpsigTestBodyJSON
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
	result := verifier.VerifyRequest(req, tampered, httpsigEd25519KeyFetcher(km))
	if result.Verified {
		t.Fatal("expected digest mismatch rejection")
	}
	if result.Reason != crypto.ReasonContentDigest {
		t.Fatalf("Reason=%q want content_digest", result.Reason)
	}
}

func TestVerifyRequest_AcceptsEmptyBodyMissingContentLengthHeader(t *testing.T) {
	km := mustHTTPSigKeyManager(t)
	opts := httpsigFixedOptions()
	verifier := crypto.NewRFC9421VerifierWithOptions(opts)

	req := httptest.NewRequest("GET", "https://example.com/ocm/discovery", nil)
	req.Host = "example.com"
	req.Header.Set("Date", opts.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT"))
	emptyDigest := base64.StdEncoding.EncodeToString(sigalg.SumSHA256(nil))
	req.Header.Set("Content-Digest", "sha-256=:"+emptyDigest+":")
	// Deliberately do NOT set Content-Length; req.ContentLength defaults to 0.

	components := httpsigAppendixBComponents
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

	result := verifier.VerifyRequest(req, nil, httpsigEd25519KeyFetcher(km))
	if !result.Verified {
		t.Fatalf("expected empty-body verify OK with missing Content-Length header (canonical fallback), got verified=false reason=%s err=%v", result.Reason, result.Error)
	}
}

func TestVerifyRequest_RejectsNonEmptyBodyMissingContentLengthHeader(t *testing.T) {
	verifier := crypto.NewRFC9421Verifier()
	now := time.Now().Unix()
	body := httpsigTestBodyJSON
	digest := httpsigContentDigestHeader(body)

	req := httptest.NewRequest("POST", "https://example.com/ocm/shares", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Digest", digest)
	// Deliberately do NOT set Content-Length.
	req.Header.Set("Date", httpsigStandardDate)
	req.Header.Set("Signature-Input", fmt.Sprintf(
		`ocm=("@method" "@target-uri" "content-digest" "content-length" "date");created=%d;keyid="example.com#key1";alg="ed25519";tag="ocm"`,
		now,
	))
	req.Header.Set("Signature", httpsigPlaceholderSigAlt)

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
