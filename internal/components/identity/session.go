// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package identity

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"
)

// Session holds an authenticated user session token and expiry.
type Session struct {
	Token     string    `json:"token"`
	UserID    string    `json:"userId"`
	CreatedAt time.Time `json:"createdAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// IsExpired reports whether the session has passed its expiry time.
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// SessionRepo provides session storage operations.
type SessionRepo interface {
	// Create creates a new session for the user.
	Create(ctx context.Context, userID string, ttl time.Duration) (*Session, error)

	// Get retrieves a session by token. Returns ErrSessionNotFound if not found.
	Get(ctx context.Context, token string) (*Session, error)

	// Delete removes a session (logout).
	Delete(ctx context.Context, token string) error

	// DeleteByUser removes all sessions for a user.
	DeleteByUser(ctx context.Context, userID string) error

	// DeleteExpired removes all expired sessions.
	DeleteExpired(ctx context.Context) (int, error)
}

// GenerateToken returns a cryptographically random session token.
func GenerateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("identity: generate session token: %w", err)
	}

	return base64.URLEncoding.EncodeToString(b), nil
}

// MemorySessionRepo is an in-memory implementation of SessionRepo.
type MemorySessionRepo struct {
	mu       sync.RWMutex
	sessions map[string]*Session // by token
	byUser   map[string][]string // userID -> tokens
}

// NewMemorySessionRepo returns an empty in-memory session store.
func NewMemorySessionRepo() *MemorySessionRepo {
	return &MemorySessionRepo{
		sessions: make(map[string]*Session),
		byUser:   make(map[string][]string),
	}
}

// Create stores a new session in the in-memory repository.
func (r *MemorySessionRepo) Create(_ context.Context, userID string, ttl time.Duration) (*Session, error) {
	token, err := GenerateToken()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	session := &Session{
		Token:     token,
		UserID:    userID,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.sessions[token] = session
	r.byUser[userID] = append(r.byUser[userID], token)

	return session, nil
}

// Get returns a session by token from the in-memory repository.
func (r *MemorySessionRepo) Get(_ context.Context, token string) (*Session, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	session, ok := r.sessions[token]
	if !ok {
		return nil, ErrSessionNotFound
	}

	if session.IsExpired() {
		return nil, ErrSessionExpired
	}

	return session, nil
}

// Delete removes a session by token from the in-memory repository.
func (r *MemorySessionRepo) Delete(_ context.Context, token string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	session, ok := r.sessions[token]
	if !ok {
		return nil
	}

	tokens := r.byUser[session.UserID]
	for i, t := range tokens {
		if t == token {
			r.byUser[session.UserID] = append(tokens[:i], tokens[i+1:]...)
			break
		}
	}

	delete(r.sessions, token)

	return nil
}

// DeleteByUser removes all sessions for a user from the in-memory repository.
func (r *MemorySessionRepo) DeleteByUser(_ context.Context, userID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	tokens := r.byUser[userID]
	for _, token := range tokens {
		delete(r.sessions, token)
	}

	delete(r.byUser, userID)

	return nil
}

// DeleteExpired removes expired sessions from the in-memory repository.
func (r *MemorySessionRepo) DeleteExpired(_ context.Context) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	var count int

	now := time.Now()

	for token, session := range r.sessions {
		if now.After(session.ExpiresAt) {
			tokens := r.byUser[session.UserID]
			for i, t := range tokens {
				if t == token {
					r.byUser[session.UserID] = append(tokens[:i], tokens[i+1:]...)
					break
				}
			}

			delete(r.sessions, token)

			count++
		}
	}

	return count, nil
}
