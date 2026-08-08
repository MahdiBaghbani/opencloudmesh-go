// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package discovery

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peerorigin"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/jwks"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/keyid"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigalg"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
)

// PeerDiscoveryAdapter implements inbound signature PeerDiscovery using JWKS.
type PeerDiscoveryAdapter struct {
	peerOrigin *peerorigin.Resolver
	jwks       *jwks.Resolver
	discovery  *Client
}

// NewPeerDiscoveryAdapter builds a peer discovery adapter backed by JWKS
// resolution. The discovery client fetches the peer's advertised discovery
// document to obtain the jwksUri.
func NewPeerDiscoveryAdapter(httpClient jwks.HTTPDoer, discoveryClient *Client) *PeerDiscoveryAdapter {
	resolver, err := jwks.NewResolverWithOptions(httpClient, jwks.ResolverOptions{
		TTL:                jwks.DefaultCacheTTL,
		MinRefetchInterval: jwks.DefaultMinRefetchInterval,
		NegativeCacheTTL:   jwks.DefaultNegativeCacheTTL,
		MaxResponseBytes:   int64(config.DefaultMaxResponseBytes),
	})
	if err != nil {
		return &PeerDiscoveryAdapter{}
	}

	if discoveryClient == nil {
		if c, ok := httpClient.(*httpclient.Client); ok {
			discoveryClient = NewClient(c, nil)
		}
	}

	return &PeerDiscoveryAdapter{
		jwks:      resolver,
		discovery: discoveryClient,
	}
}

// JWKSResolverOptions returns the effective JWKS cache and fetch policy for
// this adapter's resolver. ok is false when the adapter has no resolver
// (nil HTTP client at construction).
func (p *PeerDiscoveryAdapter) JWKSResolverOptions() (opts jwks.ResolverOptions, ok bool) {
	if p.jwks == nil {
		return jwks.ResolverOptions{}, false
	}

	return p.jwks.EffectiveOptions(), true
}

// SetPeerOrigin wires the peer-origin resolver so peer discovery follows the
// dev-mode HTTP transport gate.
func (p *PeerDiscoveryAdapter) SetPeerOrigin(peerOrigin *peerorigin.Resolver) {
	p.peerOrigin = peerOrigin
}

// ResolveVerificationKey fetches the public key for a keyId through the peer's
// advertised discovery jwksUri. It fetches the peer discovery document,
// validates the advertised jwksUri with the shared discovery validator, and
// resolves the exact key matching kid from that explicit URL.
func (p *PeerDiscoveryAdapter) ResolveVerificationKey(ctx context.Context, keyID string) (sigalg.ResolvedPublicKey, error) {
	if p.jwks == nil {
		return sigalg.ResolvedPublicKey{}, errors.New("no JWKS resolver configured")
	}

	if p.discovery == nil {
		return sigalg.ResolvedPublicKey{}, errors.New("no discovery client configured")
	}

	parsed, err := keyid.ParseKid(keyID)
	if err != nil {
		return sigalg.ResolvedPublicKey{}, fmt.Errorf("invalid keyId %q: %w", keyID, err)
	}

	scheme, authority, err := keyid.CanonicalJWKSAuthority(parsed)
	if err != nil {
		return sigalg.ResolvedPublicKey{}, fmt.Errorf("invalid keyId %q: %w", keyID, err)
	}

	// Absolute-URI kids must pass peer absolute-URI policy before discovery fetch.
	if parsed.Scheme != "" && p.peerOrigin != nil {
		if !p.peerOrigin.IsAbsoluteURIAllowed(keyID, authority) {
			return sigalg.ResolvedPublicKey{}, fmt.Errorf("absolute keyId %q is not allowed for peer %q", keyID, authority)
		}
	}

	// Host#fragment kids follow the peer transport policy. Absolute-URI kids keep
	// the scheme encoded in the keyId so strict TLS peers stay on HTTPS even when
	// the local resolver is in dev-mode HTTP transport.
	if parsed.Scheme == "" {
		decision := p.resolvePeerOrigin(authority)
		if decision.Scheme != "" {
			scheme = decision.Scheme
		}
	}

	discoveryBase := (&url.URL{Scheme: scheme, Host: authority}).String()

	disc, err := p.discovery.Discover(ctx, discoveryBase)
	if err != nil {
		return sigalg.ResolvedPublicKey{}, fmt.Errorf("peer discovery for %q: %w", keyID, err)
	}

	if disc.JwksUri == "" {
		return sigalg.ResolvedPublicKey{}, fmt.Errorf("peer discovery for %q: no jwksUri advertised", keyID)
	}

	resolved, err := p.jwks.ResolveURL(ctx, disc.JwksUri, keyID)
	if err != nil {
		return sigalg.ResolvedPublicKey{}, fmt.Errorf("jwks lookup for %q: %w", keyID, err)
	}

	return resolved, nil
}

func (p *PeerDiscoveryAdapter) resolvePeerOrigin(host string) peerorigin.Decision {
	if p.peerOrigin == nil {
		return peerorigin.Decision{}
	}

	return p.peerOrigin.Resolve(host)
}
