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
// capability. This is exactly the shape that used to trigger the removed
// capability-based signing fallback when no outbound policy was set.
func httpSigDiscovery() *discovery.Discovery {
	return &discovery.Discovery{
		EndPoint:     "https://peer.example/ocm",
		Capabilities: []string{"http-sig"},
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
		EndpointPath: "notifications",
		Kind:         outboundsigning.EndpointNotifications,
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
	want := "https://peer.example/ocm/notifications"
	if hc.gotURL != want {
		t.Fatalf("expected POST to %q, got %q", want, hc.gotURL)
	}
}

func TestSendResolved_NilPolicyRejectsShares(t *testing.T) {
	hc := &captureHTTPClient{}
	poster := outbound.NewPoster(hc, nil, newTestSigner(t), nil, nil)

	_, err := poster.SendResolved(context.Background(), outbound.Request{
		TargetHost:   "peer.example",
		EndpointPath: "shares",
		Kind:         outboundsigning.EndpointShares,
		Body:         []byte(`{}`),
	}, outbound.ResolvedPeer{
		PeerDomain: "peer.example",
		Discovery:  httpSigDiscovery(),
	})
	if err == nil {
		t.Fatal("expected error when share dispatch has nil outbound policy")
	}
	if hc.calls != 0 {
		t.Fatalf("expected no HTTP send on policy error, got %d calls", hc.calls)
	}
}

func TestSendResolved_NilPolicyRejectsInvites(t *testing.T) {
	hc := &captureHTTPClient{}
	poster := outbound.NewPoster(hc, nil, newTestSigner(t), nil, nil)

	_, err := poster.SendResolved(context.Background(), outbound.Request{
		TargetHost:   "peer.example",
		EndpointPath: "invite-accepted",
		Kind:         outboundsigning.EndpointInvites,
		Body:         []byte(`{}`),
	}, outbound.ResolvedPeer{
		PeerDomain: "peer.example",
		Discovery:  httpSigDiscovery(),
	})
	if err == nil {
		t.Fatal("expected error when invite dispatch has nil outbound policy")
	}
	if hc.calls != 0 {
		t.Fatalf("expected no HTTP send on policy error, got %d calls", hc.calls)
	}
}

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

// TestSendResolved_OffPolicySignsShares confirms share dispatch is always signed
// even when outbound_mode=off would leave other endpoint kinds unsigned.
func TestSendResolved_OffPolicySignsShares(t *testing.T) {
	hc := &captureHTTPClient{}
	poster := outbound.NewPoster(
		hc,
		nil,
		newTestSigner(t),
		&outboundsigning.OutboundPolicy{OutboundMode: "off"},
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

	if hc.gotSignature == "" {
		t.Fatal("expected signed share dispatch under outbound_mode=off")
	}
}

// TestSendResolved_CriteriaOnlySignsSharesWithoutPeerHTTPSig confirms share
// dispatch signs even when the peer discovery omits must-use-http-sig.
func TestSendResolved_CriteriaOnlySignsSharesWithoutPeerHTTPSig(t *testing.T) {
	hc := &captureHTTPClient{}
	poster := outbound.NewPoster(
		hc,
		nil,
		newTestSigner(t),
		&outboundsigning.OutboundPolicy{
			OutboundMode: "criteria-only",
		},
		nil,
	)

	disc := &discovery.Discovery{
		EndPoint:     "https://peer.example/ocm",
		Capabilities: []string{"http-sig"},
		Criteria:     []string{},
	}

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

	if hc.gotSignature == "" {
		t.Fatal("expected signed share dispatch when peer lacks must-use-http-sig")
	}
}
