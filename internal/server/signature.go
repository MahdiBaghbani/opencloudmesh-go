package server

import (
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/ocm/discovery"
)

// PeerDiscoveryAdapter is an alias for discovery.PeerDiscoveryAdapter.
// Kept for backward compatibility with tests.
type PeerDiscoveryAdapter = discovery.PeerDiscoveryAdapter

// NewPeerDiscoveryAdapter creates a new adapter.
// Delegates to discovery.NewPeerDiscoveryAdapter.
func NewPeerDiscoveryAdapter(client *discovery.Client) *PeerDiscoveryAdapter {
	return discovery.NewPeerDiscoveryAdapter(client)
}

// ExtractHostFromKeyID extracts the host from a keyId URL.
// Delegates to discovery.ExtractHostFromKeyID.
func ExtractHostFromKeyID(keyID string) (string, error) {
	return discovery.ExtractHostFromKeyID(keyID)
}
