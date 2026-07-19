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
	peerOrigin *peerorigin.Resolver
	jwks       *jwks.Resolver
}

func NewPeerDiscoveryAdapter(httpClient jwks.HTTPDoer) *PeerDiscoveryAdapter {
	resolver, err := jwks.NewResolver(httpClient)
	if err != nil {
		return &PeerDiscoveryAdapter{}
	}
	return &PeerDiscoveryAdapter{
		jwks: resolver,
	}
}

// SetPeerOrigin wires the peer-origin resolver so peer discovery follows the
// dev-mode HTTP transport gate.
func (p *PeerDiscoveryAdapter) SetPeerOrigin(peerOrigin *peerorigin.Resolver) {
	p.peerOrigin = peerOrigin
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

	// Host#fragment kids follow the peer transport policy. Absolute-URI kids keep
	// the scheme encoded in the keyId so strict TLS peers stay on HTTPS even when
	// the local resolver is in dev-mode HTTP transport.
	if parsed.Scheme == "" {
		decision := p.resolvePeerOrigin(authority)
		if decision.Scheme != "" {
			scheme = decision.Scheme
		}
	}

	resolved, err := p.jwks.Resolve(ctx, scheme, authority, keyID)
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
