package identity

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

// SeededUser defines a user to be created at startup.
type SeededUser struct {
	Username    string
	Password    string
	Email       string
	DisplayName string
	Role        string
	Realm       string
	StorageRoot string
}

// Bootstrap creates admin and seeded users idempotently.
type Bootstrap struct {
	repo PartyRepo
	auth *UserAuth
	log  *slog.Logger
}

// NewBootstrap creates a new bootstrap handler.
func NewBootstrap(repo PartyRepo, auth *UserAuth, log *slog.Logger) *Bootstrap {
	return &Bootstrap{
		repo: repo,
		auth: auth,
		log:  log,
	}
}

// Run creates the admin user and any seeded users.
// Returns the number of users created (0 if all already exist).
func (b *Bootstrap) Run(ctx context.Context, admin SeededUser, seeded []SeededUser) (int, error) {
	var created int

	// Create admin user first
	if admin.Username != "" {
		n, err := b.ensureUser(ctx, admin)
		if err != nil {
			return created, err
		}
		created += n
	}

	// Create seeded users
	for _, s := range seeded {
		n, err := b.ensureUser(ctx, s)
		if err != nil {
			return created, err
		}
		created += n
	}

	return created, nil
}

func (b *Bootstrap) ensureUser(ctx context.Context, s SeededUser) (int, error) {
	// Check if user exists
	_, err := b.repo.GetByUsername(ctx, s.Username)
	if err == nil {
		b.log.Debug("user already exists", "username", s.Username)
		return 0, nil
	}
	if !errors.Is(err, ErrUserNotFound) {
		return 0, err
	}

	// Hash password
	hash, err := b.auth.HashPassword(s.Password)
	if err != nil {
		return 0, err
	}

	role := s.Role
	if role == "" {
		role = "user"
	}

	user := &User{
		ID:           UUIDv7(),
		Username:     s.Username,
		Email:        s.Email,
		DisplayName:  s.DisplayName,
		PasswordHash: hash,
		Role:         role,
		Realm:        s.Realm,
		StorageRoot:  s.StorageRoot,
		CreatedAt:    time.Now(),
	}

	if err := b.repo.Create(ctx, user); err != nil {
		return 0, err
	}

	b.log.Info("created user", "username", s.Username, "role", role)
	return 1, nil
}

// ProbeUserTTL is the default TTL for probe users.
const ProbeUserTTL = 24 * time.Hour

// CreateProbeUser creates a temporary probe user with isolated realm and storage.
func (b *Bootstrap) CreateProbeUser(ctx context.Context, username, password, realm, storageRoot string) (*User, error) {
	// Check if user already exists
	existing, err := b.repo.GetByUsername(ctx, username)
	if err == nil {
		// User exists - check if it's a probe in the same realm
		if existing.IsProbe() && existing.Realm == realm {
			return existing, nil
		}
		return nil, ErrUserExists
	}
	if !errors.Is(err, ErrUserNotFound) {
		return nil, err
	}

	hash, err := b.auth.HashPassword(password)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	expiresAt := now.Add(ProbeUserTTL)

	user := &User{
		ID:           UUIDv7(),
		Username:     username,
		Email:        "",
		DisplayName:  "Probe User",
		PasswordHash: hash,
		Role:         "probe",
		Realm:        realm,
		StorageRoot:  storageRoot,
		CreatedAt:    now,
		ExpiresAt:    &expiresAt,
	}

	if err := b.repo.Create(ctx, user); err != nil {
		return nil, err
	}

	b.log.Info("created probe user", "username", username, "realm", realm, "expires_at", expiresAt)
	return user, nil
}
