// Package identity provides user management, authentication, and session handling.
package identity

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"sync"
	"time"
)

var (
	ErrUserNotFound           = errors.New("user not found")
	ErrUserExists             = errors.New("user already exists")
	ErrInvalidPassword        = errors.New("invalid password")
	ErrSessionExpired         = errors.New("session expired")
	ErrSessionNotFound        = errors.New("session not found")
	ErrSuperAdminProtected    = errors.New("super admin cannot be deleted or demoted")
	ErrSuperAdminRoleChange   = errors.New("super admin role cannot be changed")
)

// Role constants for user roles.
const (
	RoleUser       = "user"
	RoleAdmin      = "admin"
	RoleSuperAdmin = "super_admin"
	RoleProbe      = "probe"
)

// User represents a party (user) in the system.
type User struct {
	ID           string    `json:"id"`            // UUIDv7
	Username     string    `json:"username"`      // Unique login name
	Email        string    `json:"email"`         // Optional email
	DisplayName  string    `json:"display_name"`  // Human-readable name
	PasswordHash string    `json:"-"`             // bcrypt hash, never serialized
	Role         string    `json:"role"`          // admin, user, probe
	Realm        string    `json:"realm"`         // Isolation realm for probe users
	StorageRoot  string    `json:"storage_root"`  // User's storage root path
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"` // For probe users
}

// IsProbe returns true if the user is a probe user.
func (u *User) IsProbe() bool {
	return u.Role == RoleProbe
}

// IsAdmin returns true if the user is an admin (includes super_admin).
func (u *User) IsAdmin() bool {
	return u.Role == RoleAdmin || u.Role == RoleSuperAdmin
}

// IsSuperAdmin returns true if the user is the super admin.
func (u *User) IsSuperAdmin() bool {
	return u.Role == RoleSuperAdmin
}

// IsExpired returns true if the user has expired.
func (u *User) IsExpired() bool {
	if u.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*u.ExpiresAt)
}

// PartyRepo provides user storage operations.
type PartyRepo interface {
	// Create creates a new user. Returns ErrUserExists if username is taken.
	Create(ctx context.Context, user *User) error

	// Get retrieves a user by ID. Returns ErrUserNotFound if not found.
	Get(ctx context.Context, id string) (*User, error)

	// GetByUsername retrieves a user by username. Returns ErrUserNotFound if not found.
	GetByUsername(ctx context.Context, username string) (*User, error)

	// Update updates an existing user.
	Update(ctx context.Context, user *User) error

	// Delete removes a user by ID.
	Delete(ctx context.Context, id string) error

	// List returns all users, optionally filtered by realm.
	List(ctx context.Context, realm string) ([]*User, error)

	// DeleteExpired removes all expired probe users.
	DeleteExpired(ctx context.Context) (int, error)
}

// UUIDv7 generates a UUIDv7 (time-ordered unique identifier).
func UUIDv7() string {
	var uuid [16]byte

	// Get milliseconds since Unix epoch
	now := time.Now().UnixMilli()
	binary.BigEndian.PutUint64(uuid[0:8], uint64(now)<<16)

	// Fill rest with random bytes
	rand.Read(uuid[6:])

	// Set version (7) and variant (RFC 4122)
	uuid[6] = (uuid[6] & 0x0f) | 0x70 // Version 7
	uuid[8] = (uuid[8] & 0x3f) | 0x80 // Variant

	return formatUUID(uuid[:])
}

func formatUUID(b []byte) string {
	return string(hexEncode(b[0:4])) + "-" +
		string(hexEncode(b[4:6])) + "-" +
		string(hexEncode(b[6:8])) + "-" +
		string(hexEncode(b[8:10])) + "-" +
		string(hexEncode(b[10:16]))
}

var hexTable = []byte("0123456789abcdef")

func hexEncode(src []byte) []byte {
	dst := make([]byte, len(src)*2)
	for i, v := range src {
		dst[i*2] = hexTable[v>>4]
		dst[i*2+1] = hexTable[v&0x0f]
	}
	return dst
}

// MemoryPartyRepo is an in-memory implementation of PartyRepo.
type MemoryPartyRepo struct {
	mu          sync.RWMutex
	users       map[string]*User // by ID
	byUsername  map[string]string // username -> ID
}

// NewMemoryPartyRepo creates a new in-memory party repository.
func NewMemoryPartyRepo() *MemoryPartyRepo {
	return &MemoryPartyRepo{
		users:      make(map[string]*User),
		byUsername: make(map[string]string),
	}
}

func (r *MemoryPartyRepo) Create(ctx context.Context, user *User) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.byUsername[user.Username]; exists {
		return ErrUserExists
	}

	if user.ID == "" {
		user.ID = UUIDv7()
	}
	if user.CreatedAt.IsZero() {
		user.CreatedAt = time.Now()
	}

	// Store a copy
	u := *user
	r.users[user.ID] = &u
	r.byUsername[user.Username] = user.ID

	return nil
}

func (r *MemoryPartyRepo) Get(ctx context.Context, id string) (*User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	user, ok := r.users[id]
	if !ok {
		return nil, ErrUserNotFound
	}

	// Return a copy
	u := *user
	return &u, nil
}

func (r *MemoryPartyRepo) GetByUsername(ctx context.Context, username string) (*User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	id, ok := r.byUsername[username]
	if !ok {
		return nil, ErrUserNotFound
	}

	user := r.users[id]
	u := *user
	return &u, nil
}

func (r *MemoryPartyRepo) Update(ctx context.Context, user *User) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	existing, ok := r.users[user.ID]
	if !ok {
		return ErrUserNotFound
	}

	// Super admin role cannot be changed
	if existing.Role == RoleSuperAdmin && user.Role != RoleSuperAdmin {
		return ErrSuperAdminRoleChange
	}

	// If username changed, update the index
	if existing.Username != user.Username {
		delete(r.byUsername, existing.Username)
		r.byUsername[user.Username] = user.ID
	}

	u := *user
	r.users[user.ID] = &u
	return nil
}

func (r *MemoryPartyRepo) Delete(ctx context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	user, ok := r.users[id]
	if !ok {
		return ErrUserNotFound
	}

	// Super admin cannot be deleted
	if user.Role == RoleSuperAdmin {
		return ErrSuperAdminProtected
	}

	delete(r.byUsername, user.Username)
	delete(r.users, id)
	return nil
}

func (r *MemoryPartyRepo) List(ctx context.Context, realm string) ([]*User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []*User
	for _, user := range r.users {
		if realm == "" || user.Realm == realm {
			u := *user
			result = append(result, &u)
		}
	}
	return result, nil
}

func (r *MemoryPartyRepo) DeleteExpired(ctx context.Context) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	var count int
	now := time.Now()
	for id, user := range r.users {
		if user.ExpiresAt != nil && now.After(*user.ExpiresAt) {
			delete(r.byUsername, user.Username)
			delete(r.users, id)
			count++
		}
	}
	return count, nil
}
