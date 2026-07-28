package token

import (
	"context"
	"errors"
	"sync"
	"time"
)

var (
	// ErrTokenNotFound reports a missing issued token.
	ErrTokenNotFound = errors.New("token not found")
	// ErrTokenExpired reports an expired issued token.
	ErrTokenExpired = errors.New("token expired")
)

// TokenStore persists issued access tokens and supports lookup, deletion, and expiry cleanup.
type TokenStore interface {
	Store(ctx context.Context, token *IssuedToken) error
	Get(ctx context.Context, accessToken string) (*IssuedToken, error)
	Delete(ctx context.Context, accessToken string) error
	CleanExpired(ctx context.Context) error
}

// MemoryTokenStore holds exchanged bearer tokens in process memory only.
// Tokens are intentionally ephemeral: they are not wired through repos.New and
// do not survive restart.
type MemoryTokenStore struct {
	mu     sync.RWMutex
	tokens map[string]*IssuedToken
}

func NewMemoryTokenStore() *MemoryTokenStore { //nolint:revive // exported: trivial constructor initializing the in-memory token map
	return &MemoryTokenStore{
		tokens: make(map[string]*IssuedToken),
	}
}

// Store saves the issued token keyed by access token; implements TokenStore.
func (s *MemoryTokenStore) Store(_ context.Context, token *IssuedToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.tokens[token.AccessToken] = token

	return nil
}

// Get returns the issued token for accessToken; implements TokenStore.
func (s *MemoryTokenStore) Get(_ context.Context, accessToken string) (*IssuedToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	token, ok := s.tokens[accessToken]
	if !ok {
		return nil, ErrTokenNotFound
	}

	if token.IsExpired() {
		return nil, ErrTokenExpired
	}

	return token, nil
}

// Delete removes the token for accessToken; implements TokenStore.
func (s *MemoryTokenStore) Delete(_ context.Context, accessToken string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.tokens, accessToken)

	return nil
}

// CleanExpired removes all tokens past their ExpiresAt; implements TokenStore.
func (s *MemoryTokenStore) CleanExpired(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for k, v := range s.tokens {
		if now.After(v.ExpiresAt) {
			delete(s.tokens, k)
		}
	}

	return nil
}
