package signature_test

import (
	"context"
	"log/slog"

	sig "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/inbound/signature"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peercompat"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

type mockPeerDiscovery struct {
	signingCapable  map[string]bool
	signingErrors   map[string]error
	publicKeysPEM   map[string]string
	publicKeyErrors map[string]error
}

func (m *mockPeerDiscovery) IsSigningCapable(ctx context.Context, host string) (bool, error) {
	if err, ok := m.signingErrors[host]; ok {
		return false, err
	}
	return m.signingCapable[host], nil
}

func (m *mockPeerDiscovery) GetPublicKey(ctx context.Context, keyID string) (string, error) {
	if err, ok := m.publicKeyErrors[keyID]; ok {
		return "", err
	}
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

func newTestSignatureMiddleware(
	cfg *config.SignatureConfig,
	peerContract *peercompat.CompiledContract,
	pd sig.PeerDiscovery,
	publicOrigin string,
	logger *slog.Logger,
) *sig.SignatureMiddleware {
	return sig.NewSignatureMiddleware(
		runtimePolicyFromSignature(cfg),
		peerContract,
		pd,
		publicOrigin,
		*cfg,
		logger,
	)
}
