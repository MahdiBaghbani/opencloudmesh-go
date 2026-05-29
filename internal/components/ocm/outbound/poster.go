// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

// Package outbound centralizes the shared OCM outbound POST flow: resolve the
// peer origin, discover the peer endpoint, apply the outbound signing decision,
// and send the request. Callers own response status interpretation.
package outbound

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/outboundsigning"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peercompat"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
)

// Poster performs the shared peer-origin resolve, discovery, signing decision,
// and HTTP POST flow used by OCM outbound callers.
type Poster struct {
	httpClient      httpclient.HTTPClient
	discoveryClient *discovery.Client
	signer          *crypto.RFC9421Signer
	outboundPolicy  *outboundsigning.OutboundPolicy
	peerContract    *peercompat.CompiledContract
}

// NewPoster builds a Poster from the outbound dependency set. A nil peer
// contract keeps legacy nil-dependency origin resolution behavior.
func NewPoster(
	httpClient httpclient.HTTPClient,
	discoveryClient *discovery.Client,
	signer *crypto.RFC9421Signer,
	outboundPolicy *outboundsigning.OutboundPolicy,
	peerContract *peercompat.CompiledContract,
) *Poster {
	return &Poster{
		httpClient:      httpClient,
		discoveryClient: discoveryClient,
		signer:          signer,
		outboundPolicy:  outboundPolicy,
		peerContract:    peerContract,
	}
}

// Request describes one outbound POST to a peer's discovered OCM endpoint.
type Request struct {
	// TargetHost is the peer host[:port] or URL used for origin resolution and
	// discovery.
	TargetHost string
	// EndpointPath is appended to the discovered endpoint, e.g. "notifications".
	EndpointPath string
	// Kind selects the outbound signing endpoint classification.
	Kind outboundsigning.EndpointKind
	// Body is the already-encoded JSON request body.
	Body []byte
}

// ResolvedPeer carries peer origin and discovery that a caller has already
// fetched. Callers that discover the peer up front (for compatibility or
// policy checks) pass this to SendResolved to avoid a second discovery hop.
type ResolvedPeer struct {
	// PeerDomain is the resolved peer domain used for the signing decision.
	PeerDomain string
	// Discovery is the already-fetched peer discovery document.
	Discovery *discovery.Discovery
}

// Send resolves the peer origin, discovers the endpoint, builds and optionally
// signs the POST, and sends it. On success the caller owns the returned
// response and must close its body.
func (p *Poster) Send(ctx context.Context, req Request) (*http.Response, error) {
	origin := p.peerContract.ResolvePeerOrigin(req.TargetHost)

	disc, err := p.discoveryClient.Discover(ctx, origin.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("discovery failed for %s: %w", req.TargetHost, err)
	}

	return p.SendResolved(ctx, req, ResolvedPeer{
		PeerDomain: origin.PeerDomain,
		Discovery:  disc,
	})
}

// SendResolved builds and optionally signs the POST against an already-resolved
// peer origin and discovery, then sends it. It performs no origin resolution or
// discovery of its own. On success the caller owns the returned response and
// must close its body.
func (p *Poster) SendResolved(ctx context.Context, req Request, peer ResolvedPeer) (*http.Response, error) {
	endpointURL, err := url.JoinPath(peer.Discovery.EndPoint, req.EndpointPath)
	if err != nil {
		return nil, fmt.Errorf("failed to build %s URL: %w", req.EndpointPath, err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpointURL, bytes.NewReader(req.Body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	if err := p.applySigning(httpReq, req, peer.PeerDomain, peer.Discovery); err != nil {
		return nil, err
	}

	resp, err := p.httpClient.Do(ctx, httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	return resp, nil
}

// applySigning applies the outbound signing decision when a policy is present,
// or the legacy capability-based fallback when no policy is configured.
func (p *Poster) applySigning(
	httpReq *http.Request,
	req Request,
	peerDomain string,
	disc *discovery.Discovery,
) error {
	if p.outboundPolicy != nil {
		decision := p.outboundPolicy.ShouldSign(req.Kind, peerDomain, disc, p.signer != nil)
		if decision.Error != nil {
			return fmt.Errorf("outbound signing policy error: %w", decision.Error)
		}
		if decision.ShouldSign && p.signer != nil {
			if err := p.signer.SignRequest(httpReq, req.Body); err != nil {
				return fmt.Errorf("failed to sign request: %w", err)
			}
		}
		return nil
	}

	if p.signer != nil && disc.HasCapability("http-sig") && len(disc.PublicKeys) > 0 {
		if err := p.signer.SignRequest(httpReq, req.Body); err != nil {
			return fmt.Errorf("failed to sign request: %w", err)
		}
	}
	return nil
}
