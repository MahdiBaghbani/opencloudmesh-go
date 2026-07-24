package ocm

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	inboundsignature "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/inbound/signature"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/jwks"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigalg"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/localidentity"
)

type ocmTestPeerDiscovery struct{}

func (ocmTestPeerDiscovery) ResolveVerificationKey(_ context.Context, keyID string) (sigalg.ResolvedPublicKey, error) {
	return sigalg.ResolvedPublicKey{}, fmt.Errorf("jwks lookup for %q: %w", keyID, jwks.ErrKeyNotFound)
}

type serviceTestPeerDiscovery struct {
	publicKeys map[string]sigalg.ResolvedPublicKey
}

func (pd *serviceTestPeerDiscovery) ResolveVerificationKey(_ context.Context, keyID string) (sigalg.ResolvedPublicKey, error) {
	if key, ok := pd.publicKeys[keyID]; ok {
		return key, nil
	}
	return sigalg.ResolvedPublicKey{}, fmt.Errorf("jwks lookup for %q: %w", keyID, jwks.ErrKeyNotFound)
}

// testInputs returns baseline Inputs with a default SignatureMiddleware
// (unresolvable test peer discovery). New() now rejects a nil
// SignatureMiddleware at startup, so every constructed Inputs needs one;
// tests that exercise real signature verification override it explicitly.
func testInputs(cfg *config.Config) Inputs {
	id, err := localidentity.Derive(cfg.PublicOrigin, cfg.ExternalBasePath)
	if err != nil {
		panic("testInputs: " + err.Error())
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	return Inputs{
		PartyRepo:         identity.NewMemoryPartyRepo(),
		CodeFlow:          policy.NewCodeFlow(),
		LocalIdentity:     id,
		TokenExchangePath: "token",
		SignatureMiddleware: inboundsignature.NewSignatureMiddleware(
			ocmTestPeerDiscovery{},
			id.Origin,
			cfg.Signature,
			logger,
		),
	}
}

func setupTestInputs() Inputs {
	cfg := config.DevConfig()
	return testInputs(cfg)
}

func setupTestInputsWithOutgoingShareRepo(t *testing.T) Inputs {
	t.Helper()

	in := testInputs(config.DevConfig())
	in.OutgoingShareRepo = sharesoutgoing.NewMemoryOutgoingShareRepo()
	return in
}

// hostSigningFixture returns an RFC9421 signer and peer discovery keyed to host.
func hostSigningFixture(t *testing.T, host string) (*crypto.RFC9421Signer, *serviceTestPeerDiscovery) {
	t.Helper()

	km := crypto.NewKeyManager("", "https://"+host)
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatalf("load key manager: %v", err)
	}
	signer := crypto.NewRFC9421Signer(km)
	pd := &serviceTestPeerDiscovery{
		publicKeys: map[string]sigalg.ResolvedPublicKey{
			km.GetKeyID(): {
				KeyID:     km.GetKeyID(),
				Algorithm: sigalg.Ed25519,
				PublicKey: km.GetSigningKey().PublicKey,
				JWKKty:    "OKP",
				JWKCrv:    "Ed25519",
			},
		},
	}
	return signer, pd
}

func replaceSignatureMiddleware(in *Inputs, cfg *config.Config, pd inboundsignature.PeerDiscovery) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	in.SignatureMiddleware = inboundsignature.NewSignatureMiddleware(
		pd,
		in.LocalIdentity.Origin,
		cfg.Signature,
		logger,
	)
}

type identityCapturingTokenStore struct {
	inner    token.TokenStore
	captured *inboundsignature.PeerIdentity
}

func (s *identityCapturingTokenStore) Store(ctx context.Context, issued *token.IssuedToken) error {
	s.captured = inboundsignature.GetPeerIdentity(ctx)
	return s.inner.Store(ctx, issued)
}

func (s *identityCapturingTokenStore) Get(ctx context.Context, accessToken string) (*token.IssuedToken, error) {
	return s.inner.Get(ctx, accessToken)
}

func (s *identityCapturingTokenStore) Delete(ctx context.Context, accessToken string) error {
	return s.inner.Delete(ctx, accessToken)
}

func (s *identityCapturingTokenStore) CleanExpired(ctx context.Context) error {
	return s.inner.CleanExpired(ctx)
}

func setupSignedTokenServiceInputs(
	t *testing.T,
	pd inboundsignature.PeerDiscovery,
) (Inputs, *identityCapturingTokenStore, *sharesoutgoing.MemoryOutgoingShareRepo) {
	t.Helper()

	cfg := config.DevConfig()

	in := testInputs(cfg)
	replaceSignatureMiddleware(&in, cfg, pd)
	innerStore := token.NewMemoryTokenStore()
	spyStore := &identityCapturingTokenStore{inner: innerStore}
	shareRepo := sharesoutgoing.NewMemoryOutgoingShareRepo()

	in.CodeFlow = policy.NewCodeFlow()
	in.OutgoingShareRepo = shareRepo
	in.TokenStore = spyStore
	return in, spyStore, shareRepo
}
