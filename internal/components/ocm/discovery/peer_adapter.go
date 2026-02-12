package discovery

import (
	"context"
	"fmt"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/keyid"
)

// PeerDiscoveryAdapter implements crypto.PeerDiscovery using discovery.Client (peer verification).
type PeerDiscoveryAdapter struct {
	client *Client
}

func NewPeerDiscoveryAdapter(client *Client) *PeerDiscoveryAdapter {
	if client == nil {
		return &PeerDiscoveryAdapter{}
	}
	return &PeerDiscoveryAdapter{client: client}
}

func (p *PeerDiscoveryAdapter) IsSigningCapable(ctx context.Context, host string) (bool, error) {
	if p.client == nil {
		return false, fmt.Errorf("no discovery client configured")
	}
	baseURL := "https://" + host
	disc, err := p.client.Discover(ctx, baseURL)
	if err != nil {
		return false, fmt.Errorf("discovery failed for %s: %w", host, err)
	}

	return disc.HasCapability("http-sig"), nil
}

// GetPublicKey fetches the public key for a keyId.
func (p *PeerDiscoveryAdapter) GetPublicKey(ctx context.Context, keyID string) (string, error) {
	if p.client == nil {
		return "", fmt.Errorf("no discovery client configured")
	}

	// Extract authority from keyId (e.g., "https://example.com/ocm#key1")
	parsed, err := keyid.Parse(keyID)
	if err != nil {
		return "", fmt.Errorf("invalid keyId %q: %w", keyID, err)
	}
	authority := keyid.Authority(parsed)
	baseURL := "https://" + authority
	disc, err := p.client.Discover(ctx, baseURL)
	if err != nil {
		return "", fmt.Errorf("discovery failed for %s: %w", authority, err)
	}
	pk := disc.GetPublicKey(keyID)
	if pk == nil {
		return "", fmt.Errorf("public key %s not found in discovery", keyID)
	}

	return pk.PublicKeyPem, nil
}

