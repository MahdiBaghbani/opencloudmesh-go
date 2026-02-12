package token

import (
	"context"
	"errors"
	"sync"
	"time"
)

var (
	ErrTokenNotFound = errors.New("token not found")
	ErrTokenExpired  = errors.New("token expired")
)

type TokenStore interface {
	Store(ctx context.Context, token *IssuedToken) error
	Get(ctx context.Context, accessToken string) (*IssuedToken, error)
	Delete(ctx context.Context, accessToken string) error
	CleanExpired(ctx context.Context) error
}

type MemoryTokenStore struct {
	mu     sync.RWMutex
	tokens map[string]*IssuedToken
}

func NewMemoryTokenStore() *MemoryTokenStore {
	return &MemoryTokenStore{
		tokens: make(map[string]*IssuedToken),
	}
}

func (s *MemoryTokenStore) Store(ctx context.Context, token *IssuedToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[token.AccessToken] = token
	return nil
}

func (s *MemoryTokenStore) Get(ctx context.Context, accessToken string) (*IssuedToken, error) {
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

func (s *MemoryTokenStore) Delete(ctx context.Context, accessToken string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tokens, accessToken)
	return nil
}

func (s *MemoryTokenStore) CleanExpired(ctx context.Context) error {
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
