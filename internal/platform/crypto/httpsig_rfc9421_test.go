// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package crypto_test

import (
	"bytes"
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigalg"
)

func TestAppendixBCoveredComponents(t *testing.T) {
	components := crypto.AppendixBCoveredComponents()

	want := []string{"@method", "@target-uri", "content-digest", "content-length"}
	if len(components) != len(want) {
		t.Fatalf("components = %v", components)
	}

	for i, c := range want {
		if components[i] != c {
			t.Fatalf("components[%d] = %q, want %q", i, components[i], c)
		}
	}
}

func TestRFC9421OptionsFromConfig_NonDefaults(t *testing.T) {
	sig := config.SignatureConfig{
		Label:                 "customlabel",
		CreatedMaxAgeSeconds:  120,
		CreatedMaxSkewSeconds: 15,
		AllowedAlgorithms:     sigalg.DefaultAllowed(),
	}

	opts := crypto.RFC9421OptionsFromConfig(sig)
	if opts.Label != "customlabel" {
		t.Fatalf("Label = %q", opts.Label)
	}

	if opts.CreatedMaxAge != 120*time.Second {
		t.Fatalf("CreatedMaxAge = %v", opts.CreatedMaxAge)
	}

	if opts.CreatedMaxSkew != 15*time.Second {
		t.Fatalf("CreatedMaxSkew = %v", opts.CreatedMaxSkew)
	}

	if len(opts.AllowedAlgorithms) != len(sigalg.DefaultAllowed()) || opts.AllowedAlgorithms[0] != "ed25519" {
		t.Fatalf("AllowedAlgorithms = %v", opts.AllowedAlgorithms)
	}
}

func TestAppendixB_VectorSignVerify_Positive(t *testing.T) {
	cases := []struct {
		name   string
		method string
		target string
		body   []byte
	}{
		{
			name:   "GET empty body includes all Appendix B components",
			method: "GET",
			target: "https://example.com/.well-known/ocm",
			body:   nil,
		},
		{
			name:   "POST with body includes Appendix B digest set",
			method: "POST",
			target: "https://example.com/ocm/shares",
			body:   []byte(`{"shareWith":"alice@peer.example"}`),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			km := mustHTTPSigKeyManager(t)

			opts := httpsigFixedOptions()

			signer := crypto.NewRFC9421SignerWithOptions(km, opts)
			verifier := crypto.NewRFC9421VerifierWithOptions(opts)

			var reqBody io.Reader = http.NoBody
			if tc.body != nil {
				reqBody = bytes.NewReader(tc.body)
			}

			req, err := http.NewRequest(tc.method, tc.target, reqBody)
			if err != nil {
				t.Fatal(err)
			}

			req.Host = "example.com"
			if len(tc.body) > 0 {
				req.Header.Set("Content-Type", "application/json")
			}

			if err := signer.SignRequest(req, tc.body); err != nil {
				t.Fatalf("SignRequest: %v", err)
			}

			sigInput := req.Header.Get("Signature-Input")
			if !strings.HasPrefix(sigInput, "ocm=") {
				t.Fatalf("Signature-Input = %q, want ocm= prefix", sigInput)
			}

			for _, want := range []string{"created=", `keyid=`, `alg="ed25519"`} {
				if !strings.Contains(sigInput, want) {
					t.Fatalf("Signature-Input missing %q: %q", want, sigInput)
				}
			}

			for _, want := range []string{`"@method"`, `"@target-uri"`, `"content-digest"`, `"content-length"`} {
				if !strings.Contains(sigInput, want) {
					t.Fatalf("Signature-Input missing %q: %q", want, sigInput)
				}
			}

			if len(tc.body) == 0 {
				wantDigest := "sha-256=:" + base64.StdEncoding.EncodeToString(sigalg.SumSHA256(nil)) + ":"
				if got := req.Header.Get("Content-Digest"); got != wantDigest {
					t.Errorf("Content-Digest = %q, want %q", got, wantDigest)
				}

				if got := req.Header.Get("Content-Length"); got != "0" {
					t.Errorf("Content-Length = %q, want 0", got)
				}
			}

			result := verifier.VerifyRequest(req, tc.body, httpsigEd25519KeyFetcher(km))
			if !result.Verified {
				t.Fatalf("verification failed: %v", result.Error)
			}
		})
	}
}

func TestAppendixB_VectorVerify_Negative(t *testing.T) {
	km := mustHTTPSigKeyManager(t)

	opts := httpsigFixedOptions()

	signer := crypto.NewRFC9421SignerWithOptions(km, opts)
	verifier := crypto.NewRFC9421VerifierWithOptions(opts)

	body := httpsigTestBodyJSON

	req, err := http.NewRequest(http.MethodPost, "https://example.com/ocm/token", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}

	req.Host = "example.com"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if err := signer.SignRequest(req, body); err != nil {
		t.Fatal(err)
	}

	keyFetcher := httpsigEd25519KeyFetcher(km)

	cases := []struct {
		name    string
		mutate  func(*http.Request)
		wantErr string
	}{
		{
			name: "wrong signature tag",
			mutate: func(r *http.Request) {
				r.Header.Set("Signature-Input", strings.Replace(r.Header.Get("Signature-Input"), `tag="ocm"`, `tag="other"`, 1))
			},
			wantErr: "tag",
		},
		{
			name: "changed method after signing",
			mutate: func(r *http.Request) {
				r.Method = http.MethodGet
			},
			wantErr: "verification failed",
		},
		{
			name: "stripped Signature header",
			mutate: func(r *http.Request) {
				r.Header.Del("Signature")
			},
			wantErr: "missing Signature",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cloned := req.Clone(req.Context())
			for k, vals := range req.Header {
				cloned.Header[k] = append([]string(nil), vals...)
			}

			tc.mutate(cloned)

			result := verifier.VerifyRequest(cloned, body, keyFetcher)
			if result.Verified {
				t.Fatal("expected verification failure")
			}

			if result.Error == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}

			if !strings.Contains(strings.ToLower(result.Error.Error()), strings.ToLower(tc.wantErr)) {
				t.Fatalf("error = %v, want substring %q", result.Error, tc.wantErr)
			}
		})
	}
}
