package discovery

import (
	"context"
	"fmt"
)

// PeerDiscoveryAdapter implements crypto.PeerDiscovery using the discovery.Client.
// This adapter is used by SignatureMiddleware for peer verification.
type PeerDiscoveryAdapter struct {
	client *Client
}

// NewPeerDiscoveryAdapter creates a new adapter.
func NewPeerDiscoveryAdapter(client *Client) *PeerDiscoveryAdapter {
	if client == nil {
		return &PeerDiscoveryAdapter{}
	}
	return &PeerDiscoveryAdapter{client: client}
}

// IsSigningCapable returns true if the peer advertises http-sig capability.
func (p *PeerDiscoveryAdapter) IsSigningCapable(ctx context.Context, host string) (bool, error) {
	if p.client == nil {
		return false, fmt.Errorf("no discovery client configured")
	}

	// Discover the peer
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

	// Extract host from keyId (e.g., "https://example.com/ocm#key1")
	host, err := ExtractHostFromKeyID(keyID)
	if err != nil {
		return "", err
	}

	// Discover the peer
	baseURL := "https://" + host
	disc, err := p.client.Discover(ctx, baseURL)
	if err != nil {
		return "", fmt.Errorf("discovery failed for %s: %w", host, err)
	}

	// Find the key
	pk := disc.GetPublicKey(keyID)
	if pk == nil {
		return "", fmt.Errorf("public key %s not found in discovery", keyID)
	}

	return pk.PublicKeyPem, nil
}

// ExtractHostFromKeyID extracts the host from a keyId URL.
// Example: "https://example.com/ocm#key1" -> "example.com"
func ExtractHostFromKeyID(keyID string) (string, error) {
	// Simple extraction - keyId is typically "https://host/path#keyname"
	if len(keyID) < 8 {
		return "", fmt.Errorf("invalid keyId format: too short")
	}

	// Skip scheme
	rest := keyID
	if len(rest) > 8 && rest[:8] == "https://" {
		rest = rest[8:]
	} else if len(rest) > 7 && rest[:7] == "http://" {
		rest = rest[7:]
	}

	// Find end of host (first / or #)
	end := len(rest)
	for i, c := range rest {
		if c == '/' || c == '#' {
			end = i
			break
		}
	}

	host := rest[:end]
	if host == "" {
		return "", fmt.Errorf("invalid keyId format: no host")
	}

	return host, nil
}
