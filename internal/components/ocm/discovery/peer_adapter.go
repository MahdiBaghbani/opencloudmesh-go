package discovery

import (
	"context"
	"fmt"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peerorigin"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/jwks"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/keyid"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigalg"
)

// PeerDiscoveryAdapter implements inbound signature PeerDiscovery using JWKS.
type PeerDiscoveryAdapter struct {
	client     *Client
	peerOrigin *peerorigin.Resolver
	jwks       *jwks.Resolver
}

func NewPeerDiscoveryAdapter(client *Client, httpClient jwks.HTTPDoer) *PeerDiscoveryAdapter {
	if client == nil {
		return &PeerDiscoveryAdapter{}
	}
	resolver, err := jwks.NewResolver(httpClient)
	if err != nil {
		// Constructor rejected the HTTP client.
		return &PeerDiscoveryAdapter{client: client}
	}
	return &PeerDiscoveryAdapter{
		client: client,
		jwks:   resolver,
	}
}

// SetPeerOrigin wires the peer-origin resolver so peer discovery follows the
// dev-mode HTTP transport gate.
func (p *PeerDiscoveryAdapter) SetPeerOrigin(peerOrigin *peerorigin.Resolver) {
	p.peerOrigin = peerOrigin
}

func (p *PeerDiscoveryAdapter) IsSigningCapable(ctx context.Context, host string) (bool, error) {
	if p.client == nil {
		return false, fmt.Errorf("no discovery client configured")
	}
	baseURL := p.resolvePeerBaseURL(host)
	disc, err := p.client.Discover(ctx, baseURL)
	if err != nil {
		return false, fmt.Errorf("discovery failed for %s: %w", host, err)
	}

	return disc.RequiresHTTPSig(), nil
}

// ResolveVerificationKey fetches the public key for a keyId via /.well-known/jwks.json.
func (p *PeerDiscoveryAdapter) ResolveVerificationKey(ctx context.Context, keyID string) (sigalg.ResolvedPublicKey, error) {
	if p.jwks == nil {
		return sigalg.ResolvedPublicKey{}, fmt.Errorf("no JWKS resolver configured")
	}

	parsed, err := keyid.ParseKid(keyID)
	if err != nil {
		return sigalg.ResolvedPublicKey{}, fmt.Errorf("invalid keyId %q: %w", keyID, err)
	}

	scheme, authority, err := keyid.CanonicalJWKSAuthority(parsed)
	if err != nil {
		return sigalg.ResolvedPublicKey{}, fmt.Errorf("invalid keyId %q: %w", keyID, err)
	}

	// Absolute-URI kids must pass peer absolute-URI policy before JWKS fetch.
	if parsed.Scheme != "" && p.peerOrigin != nil {
		if !p.peerOrigin.IsAbsoluteURIAllowed(keyID, authority) {
			return sigalg.ResolvedPublicKey{}, fmt.Errorf("absolute keyId %q is not allowed for peer %q", keyID, authority)
		}
	}

	// Prefer the transport scheme from the resolved peer origin (AllowHTTP).
	baseURL := p.resolvePeerBaseURL(authority)
	if s, host, authErr := jwks.AuthorityFromBaseURL(baseURL); authErr == nil {
		scheme = s
		authority = host
	} else if decision := p.resolvePeerOrigin(authority); decision.Scheme != "" {
		scheme = decision.Scheme
	}

	resolved, err := p.jwks.Resolve(ctx, scheme, authority, keyID)
	if err != nil {
		return sigalg.ResolvedPublicKey{}, fmt.Errorf("jwks lookup for %q: %w", keyID, err)
	}
	return resolved, nil
}

func (p *PeerDiscoveryAdapter) resolvePeerBaseURL(host string) string {
	if p.peerOrigin == nil {
		return host
	}
	decision := p.peerOrigin.Resolve(host)
	return decision.BaseURL
}

func (p *PeerDiscoveryAdapter) resolvePeerOrigin(host string) peerorigin.Decision {
	if p.peerOrigin == nil {
		return peerorigin.Decision{}
	}
	return p.peerOrigin.Resolve(host)
}
