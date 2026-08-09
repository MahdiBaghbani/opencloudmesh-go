// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package identity

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"math"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	argon2Time       = 3         // Number of iterations
	argon2Memory     = 64 * 1024 // 64 MB
	argon2Threads    = 4         // Parallelism
	argon2KeyLen     = 32        // Output key length
	argon2SaltLen    = 16        // Salt length
	argon2FastMemory = 16 * 1024 // 16 MB for fast test hashing
)

// UserAuth hashes and verifies passwords with Argon2id.
type UserAuth struct {
	time    uint32
	memory  uint32
	threads uint8
	keyLen  uint32
}

// NewUserAuth creates a new UserAuth with OWASP-recommended Argon2id parameters.
func NewUserAuth() *UserAuth {
	return &UserAuth{
		time:    argon2Time,
		memory:  argon2Memory,
		threads: argon2Threads,
		keyLen:  argon2KeyLen,
	}
}

// NewUserAuthFast returns UserAuth with lower cost for tests.
func NewUserAuthFast() *UserAuth {
	return &UserAuth{
		time:    1,
		memory:  argon2FastMemory, // 16 MB
		threads: 2,
		keyLen:  argon2KeyLen,
	}
}

// HashPassword returns a PHC-formatted Argon2id hash.
func (a *UserAuth) HashPassword(password string) (string, error) {
	salt := make([]byte, argon2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("identity: generate password salt: %w", err)
	}

	hash := argon2.IDKey([]byte(password), salt, a.time, a.memory, a.threads, a.keyLen)
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, a.memory, a.time, a.threads, b64Salt, b64Hash), nil
}

// VerifyPassword returns ErrInvalidPassword if the password does not match.
func (a *UserAuth) VerifyPassword(encodedHash, password string) error {
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

	var (
		memory, time uint32
		threads      uint8
	)
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

	keyLen, ok := safeUint32Len(expectedHash)
	if !ok {
		return ErrInvalidPassword
	}

	computedHash := argon2.IDKey([]byte(password), salt, time, memory, threads, keyLen)
	if subtle.ConstantTimeCompare(expectedHash, computedHash) != 1 {
		return ErrInvalidPassword
	}

	return nil
}

// Authenticate returns the user if username and password are valid.
func (a *UserAuth) Authenticate(ctx context.Context, repo PartyRepo, username, password string) (*User, error) {
	user, err := repo.GetByUsername(ctx, username)
	if err != nil {
		return nil, fmt.Errorf("identity: get user by username: %w", err)
	}

	if user.IsExpired() {
		return nil, ErrUserNotFound
	}

	if err := a.VerifyPassword(user.PasswordHash, password); err != nil {
		return nil, err
	}

	return user, nil
}

func safeUint32Len(b []byte) (uint32, bool) {
	n := len(b)
	if n > math.MaxUint32 {
		return 0, false
	}

	return uint32(n), true
}
