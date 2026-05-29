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
)

type captureHTTPClient struct {
	calls  int
	gotURL string
}

func (c *captureHTTPClient) Do(_ context.Context, req *http.Request) (*http.Response, error) {
	c.calls++
	c.gotURL = req.URL.String()
	return &http.Response{
		StatusCode: http.StatusCreated,
		Body:       io.NopCloser(strings.NewReader(`{"ok":true}`)),
		Header:     make(http.Header),
	}, nil
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
