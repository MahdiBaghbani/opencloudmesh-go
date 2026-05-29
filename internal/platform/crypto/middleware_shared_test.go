package crypto_test

import (
	"context"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

// mockPeerDiscovery implements crypto.PeerDiscovery for testing.
type mockPeerDiscovery struct {
	signingCapable map[string]bool
	signingErrors  map[string]error
	publicKeysPEM  map[string]string // keyID -> PEM string
}

func (m *mockPeerDiscovery) IsSigningCapable(ctx context.Context, host string) (bool, error) {
	if err, ok := m.signingErrors[host]; ok {
		return false, err
	}
	return m.signingCapable[host], nil
}

func (m *mockPeerDiscovery) GetPublicKey(ctx context.Context, keyID string) (string, error) {
	if pem, ok := m.publicKeysPEM[keyID]; ok {
		return pem, nil
	}
	return "", nil
}

func runtimePolicyFromSignature(cfg *config.SignatureConfig) *policy.RuntimePolicy {
	base := config.DevConfig()
	base.Signature = *cfg
	return policy.NewRuntimePolicy(base, nil)
}
