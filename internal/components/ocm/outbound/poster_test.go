// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package outbound_test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/outbound"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
)

type captureHTTPClient struct {
	calls             int
	gotURL            string
	gotSignature      string
	gotSignatureInput string
}

func (c *captureHTTPClient) Do(_ context.Context, req *http.Request) (*http.Response, error) {
	c.calls++
	c.gotURL = req.URL.String()
	c.gotSignature = req.Header.Get("Signature")
	c.gotSignatureInput = req.Header.Get("Signature-Input")

	return &http.Response{
		StatusCode: http.StatusCreated,
		Body:       io.NopCloser(strings.NewReader(`{"ok":true}`)),
		Header:     make(http.Header),
	}, nil
}

// newTestSigner builds an in-memory RFC 9421 signer with a freshly generated
// key. No key path is set, so nothing is persisted to disk.
func newTestSigner(t *testing.T) *crypto.RFC9421Signer {
	t.Helper()

	km := crypto.NewKeyManager("", "https://local.example")
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatalf("failed to generate signing key: %v", err)
	}

	return crypto.NewRFC9421Signer(km)
}

// httpSigDiscovery returns a discovery document that advertises the http-sig
// capability.
func httpSigDiscovery() *spec.Discovery {
	return &spec.Discovery{
		EndPoint:     "https://peer.example/ocm",
		Capabilities: []string{"http-sig"},
	}
}

// noHTTPSigDiscovery returns a discovery document that does not advertise
// http-sig.
func noHTTPSigDiscovery() *spec.Discovery {
	return &spec.Discovery{
		EndPoint: "https://peer.example/ocm",
	}
}

// TestSendResolved_DoesNotDiscover proves SendResolved relies only on the
// supplied ResolvedPeer. The discovery client is nil, so any discovery attempt
// would panic; the test passing means no discovery occurred. It also confirms
// the POST targets the supplied discovery endpoint joined with the path.
func TestSendResolved_DoesNotDiscover(t *testing.T) {
	hc := &captureHTTPClient{}
	poster := outbound.NewPoster(hc, nil, newTestSigner(t), nil)

	disc := &spec.Discovery{
		EndPoint:     "https://peer.example/ocm",
		Capabilities: []string{"http-sig"},
	}

	resp, err := poster.SendResolved(context.Background(), outbound.Request{
		TargetHost:   "peer.example",
		EndpointPath: "shares",
		Kind:         outbound.EndpointShares,
		Body:         []byte(`{}`),
	}, outbound.ResolvedPeer{
		Discovery: disc,
	})
	if err != nil {
		t.Fatalf("SendResolved returned error: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck // test cleanup: resource close

	if hc.calls != 1 {
		t.Fatalf("expected exactly one HTTP send, got %d", hc.calls)
	}

	want := "https://peer.example/ocm/shares"
	if hc.gotURL != want {
		t.Fatalf("expected POST to %q, got %q", want, hc.gotURL)
	}

	if hc.gotSignature == "" {
		t.Fatal("expected signed share dispatch")
	}
}

func TestSendResolved_NilSignerRejectsShares(t *testing.T) {
	hc := &captureHTTPClient{}
	poster := outbound.NewPoster(hc, nil, nil, nil)

	resp, err := poster.SendResolved(context.Background(), outbound.Request{
		TargetHost:   "peer.example",
		EndpointPath: "shares",
		Kind:         outbound.EndpointShares,
		Body:         []byte(`{}`),
	}, outbound.ResolvedPeer{
		Discovery: httpSigDiscovery(),
	})
	if resp != nil {
		defer resp.Body.Close() //nolint:errcheck // test response body close
	}

	if err == nil {
		t.Fatal("expected error when share dispatch has nil signer")
	}

	if hc.calls != 0 {
		t.Fatalf("expected no HTTP send on signing error, got %d calls", hc.calls)
	}
}

func TestSendResolved_NilSignerRejectsInvites(t *testing.T) {
	hc := &captureHTTPClient{}
	poster := outbound.NewPoster(hc, nil, nil, nil)

	resp, err := poster.SendResolved(context.Background(), outbound.Request{
		TargetHost:   "peer.example",
		EndpointPath: "invite-accepted",
		Kind:         outbound.EndpointInvites,
		Body:         []byte(`{}`),
	}, outbound.ResolvedPeer{
		Discovery: httpSigDiscovery(),
	})
	if resp != nil {
		defer resp.Body.Close() //nolint:errcheck // test response body close
	}

	if err == nil {
		t.Fatal("expected error when invite dispatch has nil signer")
	}

	if hc.calls != 0 {
		t.Fatalf("expected no HTTP send on signing error, got %d calls", hc.calls)
	}
}

func TestSendResolved_SignerSignsShares(t *testing.T) {
	hc := &captureHTTPClient{}
	poster := outbound.NewPoster(hc, nil, newTestSigner(t), nil)

	resp, err := poster.SendResolved(context.Background(), outbound.Request{
		TargetHost:   "peer.example",
		EndpointPath: "shares",
		Kind:         outbound.EndpointShares,
		Body:         []byte(`{}`),
	}, outbound.ResolvedPeer{
		Discovery: httpSigDiscovery(),
	})
	if err != nil {
		t.Fatalf("SendResolved returned error: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck // test cleanup: resource close

	if hc.calls != 1 {
		t.Fatalf("expected exactly one HTTP send, got %d", hc.calls)
	}

	if hc.gotSignature == "" {
		t.Fatal("expected signed request with signer configured, got no Signature header")
	}
}

func TestSendResolved_PeerWithoutHTTPSig_SendsUnsigned(t *testing.T) {
	hc := &captureHTTPClient{}
	poster := outbound.NewPoster(hc, nil, newTestSigner(t), nil)

	resp, err := poster.SendResolved(context.Background(), outbound.Request{
		TargetHost:   "peer.example",
		EndpointPath: "shares",
		Kind:         outbound.EndpointShares,
		Body:         []byte(`{}`),
	}, outbound.ResolvedPeer{
		Discovery: noHTTPSigDiscovery(),
	})
	if err != nil {
		t.Fatalf("SendResolved returned error: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck // test cleanup: resource close

	if hc.calls != 1 {
		t.Fatalf("expected exactly one HTTP send, got %d", hc.calls)
	}

	if hc.gotSignature != "" || hc.gotSignatureInput != "" {
		t.Fatalf("expected unsigned request for peer without http-sig, got Signature=%q Signature-Input=%q", hc.gotSignature, hc.gotSignatureInput)
	}
}

func TestSendResolved_NoSignerPeerWithoutHTTPSig_SendsUnsigned(t *testing.T) {
	hc := &captureHTTPClient{}
	poster := outbound.NewPoster(hc, nil, nil, nil)

	resp, err := poster.SendResolved(context.Background(), outbound.Request{
		TargetHost:   "peer.example",
		EndpointPath: "shares",
		Kind:         outbound.EndpointShares,
		Body:         []byte(`{}`),
	}, outbound.ResolvedPeer{
		Discovery: noHTTPSigDiscovery(),
	})
	if err != nil {
		t.Fatalf("SendResolved returned error: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck // test cleanup: resource close

	if hc.calls != 1 {
		t.Fatalf("expected exactly one HTTP send, got %d", hc.calls)
	}

	if hc.gotSignature != "" || hc.gotSignatureInput != "" {
		t.Fatalf("expected unsigned request without signer and without http-sig peer, got Signature=%q Signature-Input=%q", hc.gotSignature, hc.gotSignatureInput)
	}
}
