// Package webdav provides WebDAV handler tests.
package webdav

import (
	"context"
	"errors"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federation"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token"
)

var errNotFound = errors.New("not found")

// mockOutgoingShareRepo is a minimal mock for testing.
type mockOutgoingShareRepo struct {
	shares map[string]*shares.OutgoingShare
}

func newMockOutgoingShareRepo() *mockOutgoingShareRepo {
	return &mockOutgoingShareRepo{shares: make(map[string]*shares.OutgoingShare)}
}

func (m *mockOutgoingShareRepo) Create(ctx context.Context, share *shares.OutgoingShare) error {
	m.shares[share.ShareID] = share
	return nil
}

func (m *mockOutgoingShareRepo) GetByID(ctx context.Context, shareID string) (*shares.OutgoingShare, error) {
	if s, ok := m.shares[shareID]; ok {
		return s, nil
	}
	return nil, errNotFound
}

func (m *mockOutgoingShareRepo) GetByProviderID(ctx context.Context, providerID string) (*shares.OutgoingShare, error) {
	for _, s := range m.shares {
		if s.ProviderID == providerID {
			return s, nil
		}
	}
	return nil, errNotFound
}

func (m *mockOutgoingShareRepo) GetByWebDAVID(ctx context.Context, webdavID string) (*shares.OutgoingShare, error) {
	for _, s := range m.shares {
		if s.WebDAVID == webdavID {
			return s, nil
		}
	}
	return nil, errNotFound
}

func (m *mockOutgoingShareRepo) GetBySharedSecret(ctx context.Context, sharedSecret string) (*shares.OutgoingShare, error) {
	for _, s := range m.shares {
		if s.SharedSecret == sharedSecret {
			return s, nil
		}
	}
	return nil, errNotFound
}

func (m *mockOutgoingShareRepo) List(ctx context.Context) ([]*shares.OutgoingShare, error) {
	result := make([]*shares.OutgoingShare, 0, len(m.shares))
	for _, s := range m.shares {
		result = append(result, s)
	}
	return result, nil
}

func (m *mockOutgoingShareRepo) Update(ctx context.Context, share *shares.OutgoingShare) error {
	m.shares[share.ShareID] = share
	return nil
}

// mockTokenStore is a minimal mock for testing.
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

// TestValidateCredential_LenientModeRelaxation tests that peer profile relaxation
// allows sharedSecret when profile.RelaxMustExchangeToken=true and mode=lenient.
func TestValidateCredential_LenientModeRelaxation(t *testing.T) {
	repo := newMockOutgoingShareRepo()
	tokenStore := newMockTokenStore()

	// Create profile registry with nextcloud profile (has RelaxMustExchangeToken=true)
	registry := federation.NewProfileRegistry(nil, []federation.ProfileMapping{
		{Pattern: "nextcloud.example.com", ProfileName: "nextcloud"},
	})

	// Lenient mode settings
	settings := &Settings{WebDAVTokenExchangeMode: "lenient"}

	handler := NewHandler(repo, tokenStore, settings, registry, nil)

	// Create share with must-exchange-token from a Nextcloud peer
	share := &shares.OutgoingShare{
		ShareID:           "share-1",
		SharedSecret:      "secret123",
		MustExchangeToken: true,
		ReceiverHost:      "nextcloud.example.com",
	}

	ctx := context.Background()

	// Should succeed: lenient mode + nextcloud profile relaxes must-exchange-token
	authorized, method := handler.validateCredential(ctx, share, "secret123", "bearer")
	if !authorized {
		t.Error("expected authorization to succeed with lenient mode and nextcloud profile")
	}
	if method != "shared_secret" {
		t.Errorf("expected method 'shared_secret', got %q", method)
	}
}

// TestValidateCredential_StrictModeIgnoresRelaxation tests that strict mode
// ignores peer profile relaxations.
func TestValidateCredential_StrictModeIgnoresRelaxation(t *testing.T) {
	repo := newMockOutgoingShareRepo()
	tokenStore := newMockTokenStore()

	// Create profile registry with nextcloud profile (has RelaxMustExchangeToken=true)
	registry := federation.NewProfileRegistry(nil, []federation.ProfileMapping{
		{Pattern: "nextcloud.example.com", ProfileName: "nextcloud"},
	})

	// Strict mode settings
	settings := &Settings{WebDAVTokenExchangeMode: "strict"}

	handler := NewHandler(repo, tokenStore, settings, registry, nil)

	// Create share with must-exchange-token from a Nextcloud peer
	share := &shares.OutgoingShare{
		ShareID:           "share-1",
		SharedSecret:      "secret123",
		MustExchangeToken: true,
		ReceiverHost:      "nextcloud.example.com",
	}

	ctx := context.Background()

	// Should fail: strict mode ignores profile relaxations
	authorized, _ := handler.validateCredential(ctx, share, "secret123", "bearer")
	if authorized {
		t.Error("expected authorization to fail in strict mode despite nextcloud profile")
	}
}

// TestValidateCredential_BasicAuthPatternRejection tests that Basic auth patterns
// not in AllowedBasicAuthPatterns are rejected.
func TestValidateCredential_BasicAuthPatternRejection(t *testing.T) {
	repo := newMockOutgoingShareRepo()
	tokenStore := newMockTokenStore()

	// Create profile that only allows specific patterns
	restrictiveProfile := &federation.Profile{
		Name:                     "restrictive",
		AllowedBasicAuthPatterns: []string{"token:"}, // Only allow token: pattern
	}

	registry := federation.NewProfileRegistry(
		map[string]*federation.Profile{"restrictive": restrictiveProfile},
		[]federation.ProfileMapping{
			{Pattern: "restrictive.example.com", ProfileName: "restrictive"},
		},
	)

	settings := &Settings{WebDAVTokenExchangeMode: "lenient"}
	handler := NewHandler(repo, tokenStore, settings, registry, nil)

	// Create share without must-exchange-token
	share := &shares.OutgoingShare{
		ShareID:           "share-1",
		SharedSecret:      "secret123",
		MustExchangeToken: false,
		ReceiverHost:      "restrictive.example.com",
	}

	ctx := context.Background()

	// Should fail: id:token pattern not in AllowedBasicAuthPatterns
	authorized, _ := handler.validateCredential(ctx, share, "secret123", "basic:id:token")
	if authorized {
		t.Error("expected authorization to fail for disallowed Basic auth pattern")
	}

	// Should succeed: token: pattern is allowed
	authorized, method := handler.validateCredential(ctx, share, "secret123", "basic:token:")
	if !authorized {
		t.Error("expected authorization to succeed for allowed Basic auth pattern")
	}
	if method != "shared_secret" {
		t.Errorf("expected method 'shared_secret', got %q", method)
	}
}

// TestValidateCredential_EmptyPatternListAllowsAll tests that an empty
// AllowedBasicAuthPatterns list allows all patterns.
func TestValidateCredential_EmptyPatternListAllowsAll(t *testing.T) {
	repo := newMockOutgoingShareRepo()
	tokenStore := newMockTokenStore()

	// Use default strict profile which has empty AllowedBasicAuthPatterns
	registry := federation.NewProfileRegistry(nil, nil)

	settings := &Settings{WebDAVTokenExchangeMode: "off"} // off mode to skip must-exchange-token
	handler := NewHandler(repo, tokenStore, settings, registry, nil)

	share := &shares.OutgoingShare{
		ShareID:           "share-1",
		SharedSecret:      "secret123",
		MustExchangeToken: false,
		ReceiverHost:      "unknown.example.com", // Will use strict profile
	}

	ctx := context.Background()

	// All patterns should be allowed with empty AllowedBasicAuthPatterns
	patterns := []string{"basic:token:", "basic:token:token", "basic::token", "basic:id:token"}
	for _, pattern := range patterns {
		authorized, _ := handler.validateCredential(ctx, share, "secret123", pattern)
		if !authorized {
			t.Errorf("expected authorization to succeed for pattern %q with empty AllowedBasicAuthPatterns", pattern)
		}
	}
}

// TestValidateCredential_NoProfileRegistry tests fallback to strict profile
// when no profile registry is configured.
func TestValidateCredential_NoProfileRegistry(t *testing.T) {
	repo := newMockOutgoingShareRepo()
	tokenStore := newMockTokenStore()

	// No profile registry
	settings := &Settings{WebDAVTokenExchangeMode: "lenient"}
	handler := NewHandler(repo, tokenStore, settings, nil, nil)

	// Create share with must-exchange-token
	share := &shares.OutgoingShare{
		ShareID:           "share-1",
		SharedSecret:      "secret123",
		MustExchangeToken: true,
		ReceiverHost:      "nextcloud.example.com",
	}

	ctx := context.Background()

	// Should fail: no registry means strict profile, which doesn't relax
	authorized, _ := handler.validateCredential(ctx, share, "secret123", "bearer")
	if authorized {
		t.Error("expected authorization to fail without profile registry (falls back to strict)")
	}
}

// TestValidateCredential_ExchangedTokenAlwaysWorks tests that exchanged tokens
// always work regardless of mode or profile.
func TestValidateCredential_ExchangedTokenAlwaysWorks(t *testing.T) {
	repo := newMockOutgoingShareRepo()
	tokenStore := newMockTokenStore()

	// Store an exchanged token
	ctx := context.Background()
	issuedToken := &token.IssuedToken{
		AccessToken: "exchanged-token-123",
		ShareID:     "share-1",
	}
	_ = tokenStore.Store(ctx, issuedToken)

	// Strict mode with no relaxation profile
	registry := federation.NewProfileRegistry(nil, nil)
	settings := &Settings{WebDAVTokenExchangeMode: "strict"}
	handler := NewHandler(repo, tokenStore, settings, registry, nil)

	// Create share with must-exchange-token
	share := &shares.OutgoingShare{
		ShareID:           "share-1",
		SharedSecret:      "wrong-secret",
		MustExchangeToken: true,
		ReceiverHost:      "unknown.example.com",
	}

	// Should succeed: exchanged token always works
	authorized, method := handler.validateCredential(ctx, share, "exchanged-token-123", "bearer")
	if !authorized {
		t.Error("expected authorization to succeed with valid exchanged token")
	}
	if method != "exchanged_token" {
		t.Errorf("expected method 'exchanged_token', got %q", method)
	}
}

// TestValidateCredential_UnknownPeerUsesStrictProfile tests that unknown peers
// use the strict profile behavior.
func TestValidateCredential_UnknownPeerUsesStrictProfile(t *testing.T) {
	repo := newMockOutgoingShareRepo()
	tokenStore := newMockTokenStore()

	// Registry with nextcloud mapping but no mapping for unknown peer
	registry := federation.NewProfileRegistry(nil, []federation.ProfileMapping{
		{Pattern: "nextcloud.example.com", ProfileName: "nextcloud"},
	})

	settings := &Settings{WebDAVTokenExchangeMode: "lenient"}
	handler := NewHandler(repo, tokenStore, settings, registry, nil)

	// Create share with must-exchange-token from unknown peer
	share := &shares.OutgoingShare{
		ShareID:           "share-1",
		SharedSecret:      "secret123",
		MustExchangeToken: true,
		ReceiverHost:      "unknown.example.com", // No mapping -> strict profile
	}

	ctx := context.Background()

	// Should fail: unknown peer uses strict profile which doesn't relax
	authorized, _ := handler.validateCredential(ctx, share, "secret123", "bearer")
	if authorized {
		t.Error("expected authorization to fail for unknown peer (uses strict profile)")
	}
}
