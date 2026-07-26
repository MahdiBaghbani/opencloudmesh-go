package crypto_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
)

func TestSignVerifyRoundTrip_RealTransport(t *testing.T) {
	km := mustHTTPSigKeyManager(t)
	opts := crypto.DefaultRFC9421Options()
	signer := crypto.NewRFC9421SignerWithOptions(km, opts)
	verifier := crypto.NewRFC9421VerifierWithOptions(opts)

	var (
		gotSignatureInput string
		gotVerified       bool
	)

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSignatureInput = r.Header.Get("Signature-Input")
		result := verifier.VerifyRequest(r, nil, httpsigEd25519KeyFetcher(km))
		gotVerified = result.Verified

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL+"/ocm/discovery", nil)
	if err != nil {
		t.Fatal(err)
	}

	if err := signer.SignRequest(req, nil); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}

	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	defer resp.Body.Close()

	if !strings.Contains(gotSignatureInput, `"content-length"`) {
		t.Fatalf("server-observed Signature-Input = %q, want content-length coverage for an empty body", gotSignatureInput)
	}

	if !gotVerified {
		t.Fatal("expected server-side verification of the empty-body request to succeed")
	}
}
