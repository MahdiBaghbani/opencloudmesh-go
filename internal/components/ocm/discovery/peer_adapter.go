package discovery

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peercompat"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/jwks"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/keyid"
)

// PeerDiscoveryAdapter implements crypto.PeerDiscovery using JWKS resolution.
type PeerDiscoveryAdapter struct {
	client       *Client
	peerContract *peercompat.CompiledContract
	jwks         *jwks.Resolver
}

func NewPeerDiscoveryAdapter(client *Client, httpClient jwks.HTTPDoer) *PeerDiscoveryAdapter {
	if client == nil {
		return &PeerDiscoveryAdapter{}
	}
	return &PeerDiscoveryAdapter{
		client: client,
		jwks:   jwks.NewResolver(httpClient),
	}
}

// SetPeerContract wires the compiled compatibility contract so peer discovery
// follows the shared peer-origin resolver.
func (p *PeerDiscoveryAdapter) SetPeerContract(peerContract *peercompat.CompiledContract) {
	p.peerContract = peerContract
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

// GetPublicKey fetches the public key for a keyId via /.well-known/jwks.json.
func (p *PeerDiscoveryAdapter) GetPublicKey(ctx context.Context, keyID string) (string, error) {
	if p.jwks == nil {
		return "", fmt.Errorf("no JWKS resolver configured")
	}

	parsed, err := keyid.ParseKid(keyID)
	if err != nil {
		return "", fmt.Errorf("invalid keyId %q: %w", keyID, err)
	}

	scheme := parsed.Scheme
	if scheme == "" {
		scheme = "https"
	}
	authority := parsed.Authority
	baseURL := p.resolvePeerBaseURL(parsed.Authority)
	if s, host, authErr := jwks.AuthorityFromBaseURL(baseURL); authErr == nil {
		scheme = s
		authority = host
	}

	pub, err := p.jwks.Resolve(ctx, scheme, authority, keyID)
	if err != nil {
		return "", fmt.Errorf("jwks lookup for %q: %w", keyID, err)
	}

	return ed25519PublicKeyPEM(pub)
}

func ed25519PublicKeyPEM(pub ed25519.PublicKey) (string, error) {
	pkix, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("marshal public key: %w", err)
	}
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: pkix}
	return string(pem.EncodeToMemory(block)), nil
}

func (p *PeerDiscoveryAdapter) resolvePeerBaseURL(host string) string {
	if p.peerContract == nil {
		return host
	}
	decision := p.peerContract.ResolvePeerOrigin(host)
	return decision.BaseURL
}
