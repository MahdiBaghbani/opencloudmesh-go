package crypto_test

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigalg"
	"net/http"
	"strings"
	"testing"
)

func TestSignRequest_CoversAllComponentsOnEmptyBody(t *testing.T) {
	km := mustHTTPSigKeyManager(t)
	opts := httpsigFixedOptions()
	signer := crypto.NewRFC9421SignerWithOptions(km, opts)

	req, err := http.NewRequest("GET", "https://example.com/ocm/discovery", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "example.com"

	if err := signer.SignRequest(req, nil); err != nil {
		t.Fatalf("SignRequest: %v", err)
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
}

func TestSignRequest_CoversAllComponentsOnNonEmptyBody(t *testing.T) {
	km := mustHTTPSigKeyManager(t)
	opts := httpsigFixedOptions()
	signer := crypto.NewRFC9421SignerWithOptions(km, opts)

	body := httpsigTestBodyJSON
	req, err := http.NewRequest("POST", "https://example.com/ocm/shares", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "example.com"

	if err := signer.SignRequest(req, body); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}

	sigInput := req.Header.Get("Signature-Input")
	for _, want := range []string{`"@method"`, `"@target-uri"`, `"content-digest"`, `"content-length"`, `"date"`} {
		if !strings.Contains(sigInput, want) {
			t.Fatalf("Signature-Input missing %s: %q", want, sigInput)
		}
	}
}

func TestVerifyRequest_RequiresAllComponentsOnEmptyBody(t *testing.T) {
	km := mustHTTPSigKeyManager(t)
	opts := httpsigFixedOptions()
	verifier := crypto.NewRFC9421VerifierWithOptions(opts)

	tests := []struct {
		name       string
		components []string
	}{
		{
			name:       "missing @method",
			components: []string{"@target-uri", "content-digest", "content-length", "date"},
		},
		{
			name:       "missing @target-uri",
			components: []string{"@method", "content-digest", "content-length", "date"},
		},
		{
			name:       "missing content-digest",
			components: []string{"@method", "@target-uri", "content-length", "date"},
		},
		{
			name:       "missing content-length",
			components: []string{"@method", "@target-uri", "content-digest", "date"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "https://example.com/ocm/discovery", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Host = "example.com"
			req.Header.Set(
				"Content-Digest",
				"sha-256=:"+base64.StdEncoding.EncodeToString(sigalg.SumSHA256(nil))+":",
			)
			req.Header.Set("Content-Length", "0")
			req.Header.Set("Date", opts.Now().UTC().Format(http.TimeFormat))

			sigInput := fmt.Sprintf(
				`ocm=("%s");created=%d;keyid=%q;alg="ed25519";tag="ocm"`,
				strings.Join(tc.components, `" "`),
				opts.Now().Unix(),
				km.GetKeyID(),
			)
			sigBase, err := crypto.BuildSignatureBase(req, tc.components)
			if err != nil {
				t.Fatalf("BuildSignatureBase: %v", err)
			}
			paramsRaw := strings.TrimPrefix(sigInput, "ocm=")
			fullBase := sigBase + fmt.Sprintf(`"@signature-params": %s`, paramsRaw)
			sig, err := km.Sign([]byte(fullBase))
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			req.Header.Set("Signature-Input", sigInput)
			req.Header.Set(
				"Signature",
				fmt.Sprintf("ocm=:%s:", base64.StdEncoding.EncodeToString(sig)),
			)

			result := verifier.VerifyRequest(req, nil, httpsigEd25519KeyFetcher(km))
			if result.Verified {
				t.Fatal("expected verification failure when a body component is omitted")
			}
		})
	}
}

func TestVerifyRequest_AcceptsMissingDate(t *testing.T) {
	km := mustHTTPSigKeyManager(t)
	opts := httpsigFixedOptions()
	// Verifier uses the default/config component policy, which defaults to
	// the date-free mandatory set; date is a SHOULD, not MUST.
	// See:
	//   - Signing requirements: https://github.com/cs3org/OCM-API/blob/a5b5da6/IETF-OCM.md#L821-L834
	//   - Verification requirements: https://github.com/cs3org/OCM-API/blob/a5b5da6/IETF-OCM.md#L860-L864
	verifier := crypto.NewRFC9421VerifierWithOptions(opts)

	components := []string{"@method", "@target-uri", "content-digest", "content-length"}
	req, err := http.NewRequest("GET", "https://example.com/ocm/discovery", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "example.com"
	req.Header.Set(
		"Content-Digest",
		"sha-256=:"+base64.StdEncoding.EncodeToString(sigalg.SumSHA256(nil))+":",
	)
	req.Header.Set("Content-Length", "0")
	// Intentionally omit the Date header: date is a SHOULD component, not
	// mandatory for verification.

	sigInput := fmt.Sprintf(
		`ocm=("%s");created=%d;keyid=%q;alg="ed25519";tag="ocm"`,
		strings.Join(components, `" "`),
		opts.Now().Unix(),
		km.GetKeyID(),
	)
	sigBase, err := crypto.BuildSignatureBase(req, components)
	if err != nil {
		t.Fatalf("BuildSignatureBase: %v", err)
	}
	paramsRaw := strings.TrimPrefix(sigInput, "ocm=")
	fullBase := sigBase + fmt.Sprintf(`"@signature-params": %s`, paramsRaw)
	sig, err := km.Sign([]byte(fullBase))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	req.Header.Set("Signature-Input", sigInput)
	req.Header.Set(
		"Signature",
		fmt.Sprintf("ocm=:%s:", base64.StdEncoding.EncodeToString(sig)),
	)

	result := verifier.VerifyRequest(req, nil, httpsigEd25519KeyFetcher(km))
	if !result.Verified {
		t.Fatalf("expected verification success when date is omitted: %v", result.Error)
	}
}
