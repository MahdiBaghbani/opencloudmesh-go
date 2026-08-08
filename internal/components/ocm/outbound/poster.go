// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// Package outbound centralizes the shared OCM outbound POST flow: resolve the
// peer origin, discover the peer endpoint, sign when configured, and send the
// request. Callers own response status interpretation.
package outbound

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peerorigin"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
)

// Poster performs the shared peer-origin resolve, discovery, signing, and HTTP
// POST flow used by OCM outbound callers.
type Poster struct {
	httpClient      httpclient.HTTPClient
	discoveryClient *discovery.Client
	signer          *crypto.RFC9421Signer
	peerOrigin      *peerorigin.Resolver
}

// NewPoster builds a Poster from the outbound dependency set. A nil peer
// origin resolver preserves nil-dependency origin resolution behavior.
func NewPoster(
	httpClient httpclient.HTTPClient,
	discoveryClient *discovery.Client,
	signer *crypto.RFC9421Signer,
	peerOrigin *peerorigin.Resolver,
) *Poster {
	return &Poster{
		httpClient:      httpClient,
		discoveryClient: discoveryClient,
		signer:          signer,
		peerOrigin:      peerOrigin,
	}
}

// Request describes one outbound POST to a peer's discovered OCM endpoint.
type Request struct {
	// TargetHost is the peer host[:port] or URL used for origin resolution and
	// discovery.
	TargetHost string
	// EndpointPath is appended to the discovered endpoint, e.g. "shares".
	EndpointPath string
	// Kind selects the outbound signing endpoint classification.
	Kind EndpointKind
	// Body is the already-encoded JSON request body.
	Body []byte
}

// ResolvedPeer carries peer origin and discovery that a caller has already
// fetched. Callers that discover the peer up front pass this to SendResolved to
// avoid a second discovery hop.
type ResolvedPeer struct {
	// Discovery is the already-fetched peer discovery document.
	Discovery *spec.Discovery
}

// Send resolves the peer origin, discovers the endpoint, builds and optionally
// signs the POST, and sends it. On success the caller owns the returned
// response and must close its body.
func (p *Poster) Send(ctx context.Context, req Request) (*http.Response, error) {
	origin := p.peerOrigin.Resolve(req.TargetHost)

	disc, err := p.discoveryClient.Discover(ctx, origin.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("discovery failed for %s: %w", req.TargetHost, err)
	}

	return p.SendResolved(ctx, req, ResolvedPeer{
		Discovery: disc,
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

	if signErr := p.applySigning(httpReq, req, peer.Discovery); signErr != nil {
		return nil, signErr
	}

	resp, err := p.httpClient.Do(ctx, httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	return resp, nil
}

func (p *Poster) applySigning(httpReq *http.Request, req Request, disc *spec.Discovery) error {
	switch req.Kind {
	case EndpointShares, EndpointInvites:
		// Only sign when the peer advertises the http-sig capability.
		// A server implementing http-sig MUST use it when interacting with a
		// peer advertising http-sig, and MAY interact unsigned with a peer not
		// advertising http-sig.
		// See https://github.com/cs3org/OCM-API/blob/6a0586183cbef10ecae9dedc42561806447eb2f5/IETF-OCM.md#L808-L823
		if !disc.IsHTTPSigCapable() {
			return nil
		}

		if p.signer == nil {
			return errors.New("outbound signing requires a configured signer")
		}

		if err := p.signer.SignRequest(httpReq, req.Body); err != nil {
			return fmt.Errorf("failed to sign request: %w", err)
		}
	}

	return nil
}
