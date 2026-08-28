// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package httpsigprobe

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
)

type captureDoer struct {
	urls []string
	sigs []string
	pass int
	fail int
}

func (c *captureDoer) DoSigned(_ context.Context, req *http.Request) (*http.Response, error) {
	c.urls = append(c.urls, req.URL.String())
	c.sigs = append(c.sigs, req.Header.Get("Signature"))

	status := c.pass
	if strings.HasSuffix(req.Header.Get("Signature"), "x") {
		status = c.fail
	}

	return &http.Response{
		StatusCode: status,
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader("")),
	}, nil
}

func newTestSigner(t *testing.T) *crypto.RFC9421Signer {
	t.Helper()

	km := crypto.NewKeyManager("", "https://local.example")
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatalf("LoadOrGenerate: %v", err)
	}

	return crypto.NewRFC9421Signer(km)
}

func TestProbeURL_IsDummyAndNeverShares(t *testing.T) {
	t.Parallel()

	got := ProbeURL("https://peer.example/ocm")
	if !strings.HasSuffix(got, "/.well-known/ocm-httpsig-probe") {
		t.Fatalf("ProbeURL = %q, want dummy well-known path", got)
	}

	if strings.Contains(strings.ToLower(got), "shares") {
		t.Fatalf("ProbeURL = %q must not mention shares", got)
	}

	if EndpointID != "httpsig-probe" {
		t.Fatalf("EndpointID = %q, want httpsig-probe", EndpointID)
	}
}

func TestProbe_AlwaysSignsAndDifferentiates(t *testing.T) {
	t.Parallel()

	doer := &captureDoer{pass: http.StatusNotFound, fail: http.StatusUnauthorized}
	got := Probe(t.Context(), Input{
		HTTP:   doer,
		Signer: newTestSigner(t),
		Origin: "https://peer.example",
	})

	if got.Grade != GradePass || got.ReasonCode != ReasonOK {
		t.Fatalf("grade=%q reason=%q, want pass/%s", got.Grade, got.ReasonCode, ReasonOK)
	}

	if len(doer.urls) != 2 || len(doer.sigs) != 2 {
		t.Fatalf("calls=%d sigs=%d, want 2 signed requests", len(doer.urls), len(doer.sigs))
	}

	for i, url := range doer.urls {
		if strings.Contains(strings.ToLower(url), "shares") {
			t.Fatalf("request %d url %q must not target shares", i, url)
		}

		if doer.sigs[i] == "" {
			t.Fatalf("request %d was not signed", i)
		}
	}

	if doer.sigs[0] == doer.sigs[1] {
		t.Fatal("tampered signature must differ from the valid signature")
	}
}

func TestProbe_SameStatusIsFail(t *testing.T) {
	t.Parallel()

	doer := &captureDoer{pass: http.StatusNotFound, fail: http.StatusNotFound}
	got := Probe(t.Context(), Input{
		HTTP:   doer,
		Signer: newTestSigner(t),
		Origin: "https://peer.example",
	})

	if got.Grade != GradeFail || got.ReasonCode != ReasonNoDifferential {
		t.Fatalf("grade=%q reason=%q, want fail/%s", got.Grade, got.ReasonCode, ReasonNoDifferential)
	}
}

func TestProbe_HonorsConfiguredResponseLimit(t *testing.T) {
	t.Parallel()

	got := Probe(t.Context(), Input{
		HTTP: limitedDoer{
			status: http.StatusNotFound,
			body:   strings.Repeat("x", 32),
			limit:  8,
		},
		Signer: newTestSigner(t),
		Origin: "https://peer.example",
	})

	if got.Grade != GradeFail || got.ReasonCode != ReasonSendFailed {
		t.Fatalf("grade=%q reason=%q, want fail/%s", got.Grade, got.ReasonCode, ReasonSendFailed)
	}

	if got.Valid.Err == nil || !strings.Contains(got.Valid.Err.Error(), "too large") {
		t.Fatalf("valid err = %v, want too large", got.Valid.Err)
	}
}

type limitedDoer struct {
	status int
	body   string
	limit  int64
}

func (d limitedDoer) DoSigned(_ context.Context, _ *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: d.status,
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader(d.body)),
	}, nil
}

func (d limitedDoer) MaxResponseBytes() int64 {
	return d.limit
}

func TestProbe_MissingSignerOrClient(t *testing.T) {
	t.Parallel()

	missingSigner := Probe(t.Context(), Input{HTTP: &captureDoer{}, Origin: "https://peer.example"})
	if missingSigner.Grade != GradeFail || missingSigner.ReasonCode != ReasonSignerMissing {
		t.Fatalf("missing signer = %q/%q", missingSigner.Grade, missingSigner.ReasonCode)
	}

	missingClient := Probe(t.Context(), Input{Signer: newTestSigner(t), Origin: "https://peer.example"})
	if missingClient.Grade != GradeFail || missingClient.ReasonCode != ReasonClientMissing {
		t.Fatalf("missing client = %q/%q", missingClient.Grade, missingClient.ReasonCode)
	}

	if missingSigner.Valid.SigRaw != "" || missingClient.Valid.SigRaw != "" {
		t.Fatal("missing deps must not emit a signed product request")
	}
}
