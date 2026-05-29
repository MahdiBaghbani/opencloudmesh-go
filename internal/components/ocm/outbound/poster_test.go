// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package outbound_test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/outbound"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/outboundsigning"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
)

type captureHTTPClient struct {
	calls        int
	gotURL       string
	gotSignature string
}

func (c *captureHTTPClient) Do(_ context.Context, req *http.Request) (*http.Response, error) {
	c.calls++
	c.gotURL = req.URL.String()
	c.gotSignature = req.Header.Get("Signature")
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
// capability and a public key. This is exactly the shape that used to trigger
// the legacy capability-based signing fallback when no outbound policy was set.
func httpSigDiscovery() *discovery.Discovery {
	return &discovery.Discovery{
		EndPoint:     "https://peer.example/ocm",
		Capabilities: []string{"http-sig"},
		PublicKeys: []discovery.PublicKey{{
			KeyID:        "https://peer.example/ocm#key-1",
			PublicKeyPem: "test-pem",
		}},
	}
}

// TestSendResolved_DoesNotDiscover proves SendResolved relies only on the
// supplied ResolvedPeer. The discovery client is nil, so any discovery attempt
// would panic; the test passing means no discovery occurred. It also confirms
// the POST targets the supplied discovery endpoint joined with the path.
func TestSendResolved_DoesNotDiscover(t *testing.T) {
	hc := &captureHTTPClient{}
	poster := outbound.NewPoster(hc, nil, nil, nil, nil)

	disc := &discovery.Discovery{EndPoint: "https://peer.example/ocm"}
	resp, err := poster.SendResolved(context.Background(), outbound.Request{
		TargetHost:   "peer.example",
		EndpointPath: "shares",
		Kind:         outboundsigning.EndpointShares,
		Body:         []byte(`{}`),
	}, outbound.ResolvedPeer{
		PeerDomain: "peer.example",
		Discovery:  disc,
	})
	if err != nil {
		t.Fatalf("SendResolved returned error: %v", err)
	}
	defer resp.Body.Close()

	if hc.calls != 1 {
		t.Fatalf("expected exactly one HTTP send, got %d", hc.calls)
	}
	want := "https://peer.example/ocm/shares"
	if hc.gotURL != want {
		t.Fatalf("expected POST to %q, got %q", want, hc.gotURL)
	}
}

// TestSendResolved_NilPolicyDoesNotSign is the regression for removing the
// legacy capability-based signing fallback. Even with a signer available and a
// peer advertising http-sig plus a public key (the old fallback trigger), a nil
// outbound policy must send the request unsigned.
func TestSendResolved_NilPolicyDoesNotSign(t *testing.T) {
	hc := &captureHTTPClient{}
	poster := outbound.NewPoster(hc, nil, newTestSigner(t), nil, nil)

	resp, err := poster.SendResolved(context.Background(), outbound.Request{
		TargetHost:   "peer.example",
		EndpointPath: "shares",
		Kind:         outboundsigning.EndpointShares,
		Body:         []byte(`{}`),
	}, outbound.ResolvedPeer{
		PeerDomain: "peer.example",
		Discovery:  httpSigDiscovery(),
	})
	if err != nil {
		t.Fatalf("SendResolved returned error: %v", err)
	}
	defer resp.Body.Close()

	if hc.calls != 1 {
		t.Fatalf("expected exactly one HTTP send, got %d", hc.calls)
	}
	if hc.gotSignature != "" {
		t.Fatalf("expected unsigned request with nil policy, got Signature header %q", hc.gotSignature)
	}
}

// TestSendResolved_StrictPolicySigns confirms policy-driven signing is
// preserved: a strict outbound policy with a signer present signs the request.
func TestSendResolved_StrictPolicySigns(t *testing.T) {
	hc := &captureHTTPClient{}
	poster := outbound.NewPoster(
		hc,
		nil,
		newTestSigner(t),
		&outboundsigning.OutboundPolicy{OutboundMode: "strict"},
		nil,
	)

	resp, err := poster.SendResolved(context.Background(), outbound.Request{
		TargetHost:   "peer.example",
		EndpointPath: "shares",
		Kind:         outboundsigning.EndpointShares,
		Body:         []byte(`{}`),
	}, outbound.ResolvedPeer{
		PeerDomain: "peer.example",
		Discovery:  httpSigDiscovery(),
	})
	if err != nil {
		t.Fatalf("SendResolved returned error: %v", err)
	}
	defer resp.Body.Close()

	if hc.calls != 1 {
		t.Fatalf("expected exactly one HTTP send, got %d", hc.calls)
	}
	if hc.gotSignature == "" {
		t.Fatal("expected signed request under strict policy with signer, got no Signature header")
	}
}
