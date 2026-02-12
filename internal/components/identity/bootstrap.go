package identity

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log/slog"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
)

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

func NewBootstrap(repo PartyRepo, auth *UserAuth, log *slog.Logger) *Bootstrap {
	log = logutil.NoopIfNil(log)
	return &Bootstrap{
		repo: repo,
		auth: auth,
		log:  log,
	}
}

// Run creates the admin user and any seeded users; returns the count created.
func (b *Bootstrap) Run(ctx context.Context, admin SeededUser, seeded []SeededUser) (int, error) {
	var created int
	if admin.Username != "" {
		n, err := b.ensureUser(ctx, admin)
		if err != nil {
			return created, err
		}
		created += n
	}
	for _, s := range seeded {
		n, err := b.ensureUser(ctx, s)
		if err != nil {
			return created, err
		}
		created += n
	}

	return created, nil
}

// EnsureSuperAdmin creates or verifies the super admin user.
// If no super admin exists, creates one with the given username and password.
// If password is empty, generates a random password and logs it once.
// If a super admin already exists, this is a no-op (returns nil).
// Password rotation only happens when explicitPasswordSet is true.
func (b *Bootstrap) EnsureSuperAdmin(ctx context.Context, username, password string, explicitPasswordSet bool) error {
	if username == "" {
		username = "admin"
	}
	users, err := b.repo.List(ctx, "")
	if err != nil {
		return err
	}

	var existingSuperAdmin *User
	for _, u := range users {
		if u.Role == RoleSuperAdmin {
			existingSuperAdmin = u
			break
		}
	}

	if existingSuperAdmin != nil {
		if explicitPasswordSet && password != "" {
			hash, err := b.auth.HashPassword(password)
			if err != nil {
				return err
			}
			existingSuperAdmin.PasswordHash = hash
			if err := b.repo.Update(ctx, existingSuperAdmin); err != nil {
				return err
			}
			b.log.Info("super admin password rotated", "username", existingSuperAdmin.Username)
		}
		return nil
	}
	passwordGenerated := false
	if password == "" {
		password = generateRandomPassword()
		passwordGenerated = true
	}

	hash, err := b.auth.HashPassword(password)
	if err != nil {
		return err
	}

	superAdmin := &User{
		ID:           UUIDv7(),
		Username:     username,
		DisplayName:  "Super Administrator",
		PasswordHash: hash,
		Role:         RoleSuperAdmin,
		CreatedAt:    time.Now(),
	}

	if err := b.repo.Create(ctx, superAdmin); err != nil {
		return err
	}

	if passwordGenerated {
		b.log.Info("super admin created with auto-generated password",
			"username", username,
			"password", password,
			"user_id", superAdmin.ID)
	} else {
		b.log.Info("super admin created", "username", username, "user_id", superAdmin.ID)
	}

	return nil
}

func generateRandomPassword() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "changeme-" + UUIDv7()
	}
	return base64.URLEncoding.EncodeToString(b)
}

func (b *Bootstrap) ensureUser(ctx context.Context, s SeededUser) (int, error) {
	_, err := b.repo.GetByUsername(ctx, s.Username)
	if err == nil {
		b.log.Debug("user already exists", "username", s.Username)
		return 0, nil
	}
	if !errors.Is(err, ErrUserNotFound) {
		return 0, err
	}
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
