package signature_test

import (
	"context"
	"fmt"
	"log/slog"

	sig "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/inbound/signature"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigalg"
)

type mockPeerDiscovery struct {
	publicKeys      map[string]sigalg.ResolvedPublicKey
	publicKeyErrors map[string]error
}

func (m *mockPeerDiscovery) ResolveVerificationKey(ctx context.Context, keyID string) (sigalg.ResolvedPublicKey, error) {
	if err, ok := m.publicKeyErrors[keyID]; ok {
		return sigalg.ResolvedPublicKey{}, err
	}

	if key, ok := m.publicKeys[keyID]; ok {
		return key, nil
	}

	return sigalg.ResolvedPublicKey{}, fmt.Errorf("public key not found for %q", keyID)
}

func resolvedKeyFromManager(km *crypto.KeyManager) sigalg.ResolvedPublicKey {
	return sigalg.ResolvedPublicKey{
		KeyID:     km.GetKeyID(),
		Algorithm: sigalg.Ed25519,
		PublicKey: km.GetSigningKey().PublicKey,
		JWKKty:    "OKP",
		JWKCrv:    "Ed25519",
	}
}

func newTestSignatureMiddleware(
	cfg *config.SignatureConfig,
	pd sig.PeerDiscovery,
	publicOrigin string,
	logger *slog.Logger,
) *sig.SignatureMiddleware {
	return sig.NewSignatureMiddleware(
		pd,
		publicOrigin,
		*cfg,
		logger,
	)
}
