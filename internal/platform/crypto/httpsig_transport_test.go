// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package crypto_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/jwks"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigalg"
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

	if err := signer.SignRequest(req, nil); err != nil { //nolint:govet // shadow: sequential err in table-driven test is benign
		t.Fatalf("SignRequest: %v", err)
	}

	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck // test cleanup: resource close

	if !strings.Contains(gotSignatureInput, `"content-length"`) {
		t.Fatalf("server-observed Signature-Input = %q, want content-length coverage for an empty body", gotSignatureInput)
	}

	if !gotVerified {
		t.Fatal("expected server-side verification of the empty-body request to succeed")
	}
}

func TestSignVerifyRoundTrip_ExactKeyIDOverHTTPJWKS(t *testing.T) {
	km := mustHTTPSigKeyManager(t)
	opts := crypto.DefaultRFC9421Options()
	signer := crypto.NewRFC9421SignerWithOptions(km, opts)
	verifier := crypto.NewRFC9421VerifierWithOptions(opts)

	var (
		gotVerified bool
		gotKeyID    string
		gotErr      error
	)

	var srv *httptest.Server

	mux := http.NewServeMux()
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(km.JWKS()) //nolint:errcheck // test mock handler: JSON encode
	})
	mux.HandleFunc("/ocm/discovery", func(w http.ResponseWriter, r *http.Request) {
		resolver, err := jwks.NewResolver(srv.Client())
		if err != nil {
			gotErr = err

			w.WriteHeader(http.StatusInternalServerError)

			return
		}

		result := verifier.VerifyRequest(r, nil, func(keyID string) (sigalg.ResolvedPublicKey, error) { //nolint:contextcheck // test: fetcher signature is fixed by VerifyRequest; no context to thread
			return resolver.ResolveURL(context.Background(), srv.URL+"/jwks", keyID)
		})
		gotVerified = result.Verified
		gotKeyID = result.KeyID
		gotErr = result.Error

		w.WriteHeader(http.StatusOK)
	})

	srv = httptest.NewTLSServer(mux)
	defer srv.Close()

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/ocm/discovery", nil)
	if err != nil {
		t.Fatal(err)
	}

	if err := signer.SignRequest(req, nil); err != nil { //nolint:govet // shadow: sequential err in table-driven test is benign
		t.Fatalf("SignRequest: %v", err)
	}

	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck // test cleanup: resource close

	if !gotVerified {
		t.Fatalf("expected server-side verification via HTTP JWKS exact keyid match: %v", gotErr)
	}

	if gotKeyID != km.GetKeyID() {
		t.Fatalf("verified KeyID = %q, want %q", gotKeyID, km.GetKeyID())
	}
}

func TestVerifyRequest_MissingKeyIDMakesNoHTTPCall(t *testing.T) {
	var jwksRequests atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		jwksRequests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks.Set{Keys: []jwks.Key{}}) //nolint:errcheck // test mock handler: JSON encode
	}))
	defer srv.Close()

	resolver, err := jwks.NewResolver(srv.Client())
	if err != nil {
		t.Fatal(err)
	}

	verifier := crypto.NewRFC9421Verifier()
	now := time.Now().Unix()
	req := httptest.NewRequest(http.MethodPost, "https://example.com/ocm/shares", nil)
	req.Header.Set("Date", httpsigStandardDate)
	req.Header.Set("Signature-Input", fmt.Sprintf(
		`ocm=("@method" "@target-uri" "content-digest" "content-length" "date");created=%d;alg="ed25519";tag="ocm"`,
		now,
	))
	req.Header.Set("Signature", httpsigPlaceholderSigAlt)

	result := verifier.VerifyRequest(req, nil, func(keyID string) (sigalg.ResolvedPublicKey, error) {
		return resolver.ResolveURL(context.Background(), srv.URL+"/jwks", keyID)
	})
	if result.Verified {
		t.Fatal("expected missing keyid rejection")
	}

	if result.Reason != crypto.ReasonMissingKeyID {
		t.Fatalf("Reason = %q, want %q (err=%v)", result.Reason, crypto.ReasonMissingKeyID, result.Error)
	}

	if got := jwksRequests.Load(); got != 0 {
		t.Fatalf("JWKS HTTP requests = %d, want 0: missing keyid must fail before network access", got)
	}
}
