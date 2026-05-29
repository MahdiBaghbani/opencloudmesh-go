package webdav

import (
	"context"
	"errors"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peercompat"
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token"
)

var errNotFound = errors.New("not found")

type mockOutgoingShareRepo struct {
	shares map[string]*sharesoutgoing.OutgoingShare
}

func newMockOutgoingShareRepo() *mockOutgoingShareRepo {
	return &mockOutgoingShareRepo{shares: make(map[string]*sharesoutgoing.OutgoingShare)}
}

func (m *mockOutgoingShareRepo) Create(ctx context.Context, share *sharesoutgoing.OutgoingShare) error {
	m.shares[share.ShareID] = share
	return nil
}

func (m *mockOutgoingShareRepo) GetByID(ctx context.Context, shareID string) (*sharesoutgoing.OutgoingShare, error) {
	if s, ok := m.shares[shareID]; ok {
		return s, nil
	}
	return nil, errNotFound
}

func (m *mockOutgoingShareRepo) GetByProviderID(ctx context.Context, providerID string) (*sharesoutgoing.OutgoingShare, error) {
	for _, s := range m.shares {
		if s.ProviderID == providerID {
			return s, nil
		}
	}
	return nil, errNotFound
}

func (m *mockOutgoingShareRepo) GetByWebDAVID(ctx context.Context, webdavID string) (*sharesoutgoing.OutgoingShare, error) {
	for _, s := range m.shares {
		if s.WebDAVID == webdavID {
			return s, nil
		}
	}
	return nil, errNotFound
}

func (m *mockOutgoingShareRepo) GetBySharedSecret(ctx context.Context, sharedSecret string) (*sharesoutgoing.OutgoingShare, error) {
	for _, s := range m.shares {
		if s.SharedSecret == sharedSecret {
			return s, nil
		}
	}
	return nil, errNotFound
}

func (m *mockOutgoingShareRepo) List(ctx context.Context) ([]*sharesoutgoing.OutgoingShare, error) {
	result := make([]*sharesoutgoing.OutgoingShare, 0, len(m.shares))
	for _, s := range m.shares {
		result = append(result, s)
	}
	return result, nil
}

func (m *mockOutgoingShareRepo) Update(ctx context.Context, share *sharesoutgoing.OutgoingShare) error {
	m.shares[share.ShareID] = share
	return nil
}

type mockTokenStore struct {
	tokens map[string]*token.IssuedToken
}

func newMockTokenStore() *mockTokenStore {
	return &mockTokenStore{tokens: make(map[string]*token.IssuedToken)}
}

func (m *mockTokenStore) Store(ctx context.Context, t *token.IssuedToken) error {
	m.tokens[t.AccessToken] = t
	return nil
}

func (m *mockTokenStore) Get(ctx context.Context, accessToken string) (*token.IssuedToken, error) {
	if t, ok := m.tokens[accessToken]; ok {
		return t, nil
	}
	return nil, token.ErrTokenNotFound
}

func (m *mockTokenStore) Delete(ctx context.Context, accessToken string) error {
	delete(m.tokens, accessToken)
	return nil
}

func (m *mockTokenStore) CleanExpired(ctx context.Context) error {
	return nil
}

func buildContractFromRegistry(t *testing.T, registry *peercompat.ProfileRegistry) *peercompat.CompiledContract {
	t.Helper()
	contract, err := peercompat.BuildCompiledContractFromRegistry(registry)
	if err != nil {
		t.Fatalf("BuildCompiledContractFromRegistry() unexpected error: %v", err)
	}
	return contract
}

func TestValidateCredential_RejectsSharedSecretForStrictShare(t *testing.T) {
	repo := newMockOutgoingShareRepo()
	tokenStore := newMockTokenStore()

	registry := peercompat.NewProfileRegistry(nil, []peercompat.ProfileMapping{
		{Pattern: "nextcloud.example.com", Profile: "nextcloud"},
	})
	handler := NewHandler(repo, tokenStore, buildContractFromRegistry(t, registry), nil)

	share := &sharesoutgoing.OutgoingShare{
		ShareID:           "share-1",
		SharedSecret:      "secret123",
		MustExchangeToken: true,
		ReceiverHost:      "nextcloud.example.com",
	}

	ctx := context.Background()

	authorized, _ := handler.validateCredential(ctx, share, "secret123", "bearer")
	if authorized {
		t.Error("expected shared-secret authorization to fail for must-exchange-token share")
	}
}

func TestValidateCredential_BasicAuthPatternRejection(t *testing.T) {
	repo := newMockOutgoingShareRepo()
	tokenStore := newMockTokenStore()

	restrictiveProfile := &peercompat.Profile{
		Name:                     "restrictive",
		AllowedBasicAuthPatterns: []string{"token:"}, // Only allow token: pattern
	}

	registry := peercompat.NewProfileRegistry(
		map[string]*peercompat.Profile{"restrictive": restrictiveProfile},
		[]peercompat.ProfileMapping{
			{Pattern: "restrictive.example.com", Profile: "restrictive"},
		},
	)

	handler := NewHandler(repo, tokenStore, buildContractFromRegistry(t, registry), nil)

	share := &sharesoutgoing.OutgoingShare{
		ShareID:           "share-1",
		SharedSecret:      "secret123",
		MustExchangeToken: false,
		ReceiverHost:      "restrictive.example.com",
	}

	ctx := context.Background()

	authorized, _ := handler.validateCredential(ctx, share, "secret123", "basic:id:token")
	if authorized {
		t.Error("expected authorization to fail for disallowed Basic auth pattern")
	}

	authorized, method := handler.validateCredential(ctx, share, "secret123", "basic:token:")
	if !authorized {
		t.Error("expected authorization to succeed for allowed Basic auth pattern")
	}
	if method != "shared_secret" {
		t.Errorf("expected method 'shared_secret', got %q", method)
	}
}

func TestValidateCredential_EmptyPatternListAllowsAll(t *testing.T) {
	repo := newMockOutgoingShareRepo()
	tokenStore := newMockTokenStore()

	registry := peercompat.NewProfileRegistry(nil, nil)
	handler := NewHandler(repo, tokenStore, buildContractFromRegistry(t, registry), nil)

	share := &sharesoutgoing.OutgoingShare{
		ShareID:           "share-1",
		SharedSecret:      "secret123",
		MustExchangeToken: false,
		ReceiverHost:      "unknown.example.com", // Will use strict profile
	}

	ctx := context.Background()

	patterns := []string{"basic:token:", "basic:token:token", "basic::token", "basic:id:token"}
	for _, pattern := range patterns {
		authorized, _ := handler.validateCredential(ctx, share, "secret123", pattern)
		if !authorized {
			t.Errorf("expected authorization to succeed for pattern %q with empty AllowedBasicAuthPatterns", pattern)
		}
	}
}

func TestValidateCredential_NoPeerContract(t *testing.T) {
	repo := newMockOutgoingShareRepo()
	tokenStore := newMockTokenStore()
	handler := NewHandler(repo, tokenStore, nil, nil)

	// Create share with must-exchange-token
	share := &sharesoutgoing.OutgoingShare{
		ShareID:           "share-1",
		SharedSecret:      "secret123",
		MustExchangeToken: true,
		ReceiverHost:      "nextcloud.example.com",
	}

	ctx := context.Background()

	authorized, _ := handler.validateCredential(ctx, share, "secret123", "bearer")
	if authorized {
		t.Error("expected authorization to fail without peer contract (falls back to strict)")
	}
}

func TestValidateCredential_ExchangedTokenAlwaysWorks(t *testing.T) {
	repo := newMockOutgoingShareRepo()
	tokenStore := newMockTokenStore()

	ctx := context.Background()
	issuedToken := &token.IssuedToken{
		AccessToken: "exchanged-token-123",
		ShareID:     "share-1",
	}
	_ = tokenStore.Store(ctx, issuedToken)

	registry := peercompat.NewProfileRegistry(nil, nil)
	handler := NewHandler(repo, tokenStore, buildContractFromRegistry(t, registry), nil)

	// Create share with must-exchange-token
	share := &sharesoutgoing.OutgoingShare{
		ShareID:           "share-1",
		SharedSecret:      "wrong-secret",
		MustExchangeToken: true,
		ReceiverHost:      "unknown.example.com",
	}

	authorized, method := handler.validateCredential(ctx, share, "exchanged-token-123", "bearer")
	if !authorized {
		t.Error("expected authorization to succeed with valid exchanged token")
	}
	if method != "exchanged_token" {
		t.Errorf("expected method 'exchanged_token', got %q", method)
	}
}

func TestValidateCredential_UnknownPeerUsesStrictProfile(t *testing.T) {
	repo := newMockOutgoingShareRepo()
	tokenStore := newMockTokenStore()

	registry := peercompat.NewProfileRegistry(nil, []peercompat.ProfileMapping{
		{Pattern: "nextcloud.example.com", Profile: "nextcloud"},
	})
	handler := NewHandler(repo, tokenStore, buildContractFromRegistry(t, registry), nil)

	share := &sharesoutgoing.OutgoingShare{
		ShareID:           "share-1",
		SharedSecret:      "secret123",
		MustExchangeToken: true,
		ReceiverHost:      "unknown.example.com", // No mapping -> strict profile
	}

	ctx := context.Background()

	authorized, _ := handler.validateCredential(ctx, share, "secret123", "bearer")
	if authorized {
		t.Error("expected authorization to fail for unknown peer (uses strict profile)")
	}
}
