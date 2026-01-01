package identity

import (
	"context"

	"golang.org/x/crypto/bcrypt"
)

// UserAuth handles password hashing and verification.
type UserAuth struct {
	cost int // bcrypt cost factor
}

// NewUserAuth creates a new UserAuth with the given bcrypt cost.
// Cost should be at least 10 for production.
func NewUserAuth(cost int) *UserAuth {
	if cost < bcrypt.MinCost {
		cost = bcrypt.DefaultCost
	}
	return &UserAuth{cost: cost}
}

// HashPassword creates a bcrypt hash of the password.
func (a *UserAuth) HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), a.cost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// VerifyPassword checks if the password matches the hash.
// Returns ErrInvalidPassword if the password doesn't match.
func (a *UserAuth) VerifyPassword(hash, password string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
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
