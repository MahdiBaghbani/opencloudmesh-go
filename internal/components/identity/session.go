package identity

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// Session represents an active user session.
type Session struct {
	Token     string    `json:"token"`
	UserID    string    `json:"user_id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// IsExpired returns true if the session has expired.
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

// GenerateToken creates a cryptographically secure random token.
func GenerateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// MemorySessionRepo is an in-memory implementation of SessionRepo.
type MemorySessionRepo struct {
	mu       sync.RWMutex
	sessions map[string]*Session // by token
	byUser   map[string][]string // userID -> tokens
}

// NewMemorySessionRepo creates a new in-memory session repository.
func NewMemorySessionRepo() *MemorySessionRepo {
	return &MemorySessionRepo{
		sessions: make(map[string]*Session),
		byUser:   make(map[string][]string),
	}
}

func (r *MemorySessionRepo) Create(ctx context.Context, userID string, ttl time.Duration) (*Session, error) {
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

func (r *MemorySessionRepo) Get(ctx context.Context, token string) (*Session, error) {
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

func (r *MemorySessionRepo) Delete(ctx context.Context, token string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	session, ok := r.sessions[token]
	if !ok {
		return nil
	}

	// Remove from user index
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

func (r *MemorySessionRepo) DeleteByUser(ctx context.Context, userID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	tokens := r.byUser[userID]
	for _, token := range tokens {
		delete(r.sessions, token)
	}
	delete(r.byUser, userID)

	return nil
}

func (r *MemorySessionRepo) DeleteExpired(ctx context.Context) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	var count int
	now := time.Now()

	for token, session := range r.sessions {
		if now.After(session.ExpiresAt) {
			// Remove from user index
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
