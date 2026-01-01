package identity

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters (OWASP recommended for password hashing)
const (
	argon2Time    = 3         // Number of iterations
	argon2Memory  = 64 * 1024 // 64 MB
	argon2Threads = 4         // Parallelism
	argon2KeyLen  = 32        // Output key length
	argon2SaltLen = 16        // Salt length
)

// UserAuth handles password hashing and verification using Argon2id.
type UserAuth struct {
	time    uint32
	memory  uint32
	threads uint8
	keyLen  uint32
}

// NewUserAuth creates a new UserAuth with OWASP-recommended Argon2id parameters.
// The cost parameter is ignored (kept for API compatibility) - Argon2id uses fixed secure defaults.
func NewUserAuth(cost int) *UserAuth {
	return &UserAuth{
		time:    argon2Time,
		memory:  argon2Memory,
		threads: argon2Threads,
		keyLen:  argon2KeyLen,
	}
}

// NewUserAuthFast creates a UserAuth with reduced parameters for testing.
func NewUserAuthFast() *UserAuth {
	return &UserAuth{
		time:    1,
		memory:  16 * 1024, // 16 MB
		threads: 2,
		keyLen:  32,
	}
}

// HashPassword creates an Argon2id hash of the password.
// Returns a PHC-formatted string: $argon2id$v=19$m=65536,t=3,p=4$salt$hash
func (a *UserAuth) HashPassword(password string) (string, error) {
	salt := make([]byte, argon2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(password), salt, a.time, a.memory, a.threads, a.keyLen)

	// Encode in PHC format
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, a.memory, a.time, a.threads, b64Salt, b64Hash), nil
}

// VerifyPassword checks if the password matches the Argon2id hash.
// Returns ErrInvalidPassword if the password doesn't match.
func (a *UserAuth) VerifyPassword(encodedHash, password string) error {
	// Parse PHC format
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return ErrInvalidPassword
	}

	if parts[1] != "argon2id" {
		return ErrInvalidPassword
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return ErrInvalidPassword
	}

	var memory, time uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return ErrInvalidPassword
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return ErrInvalidPassword
	}

	expectedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return ErrInvalidPassword
	}

	// Compute hash with same parameters
	computedHash := argon2.IDKey([]byte(password), salt, time, memory, threads, uint32(len(expectedHash)))

	// Constant-time comparison
	if subtle.ConstantTimeCompare(expectedHash, computedHash) != 1 {
		return ErrInvalidPassword
	}

	return nil
}

// Authenticate verifies a user's credentials.
// Returns the user if credentials are valid, otherwise an error.
func (a *UserAuth) Authenticate(ctx context.Context, repo PartyRepo, username, password string) (*User, error) {
	user, err := repo.GetByUsername(ctx, username)
	if err != nil {
		return nil, err
	}

	if user.IsExpired() {
		return nil, ErrUserNotFound
	}

	if err := a.VerifyPassword(user.PasswordHash, password); err != nil {
		return nil, err
	}

	return user, nil
}
