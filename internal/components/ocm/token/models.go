// Package token implements OCM token exchange (OAuth-style).
package token

import (
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
)

// DefaultTokenTTL is the default time-to-live for access tokens.
const DefaultTokenTTL = 1 * time.Hour

// Type aliases for spec-shaped types (wire format).
// These allow existing code to use token.TokenRequest, token.TokenResponse, etc.
type (
	TokenRequest  = spec.TokenRequest
	TokenResponse = spec.TokenResponse
	OAuthError    = spec.OAuthError
)

// Re-export constants from spec package for backward compatibility.
const (
	GrantTypeAuthorizationCode = spec.GrantTypeAuthorizationCode
	GrantTypeOCMShare          = spec.GrantTypeOCMShare
	ErrorInvalidRequest = spec.ErrorInvalidRequest
	ErrorInvalidGrant   = spec.ErrorInvalidGrant
	ErrorInvalidClient  = spec.ErrorInvalidClient
	ErrorUnauthorized   = spec.ErrorUnauthorized
)

// IssuedToken represents a stored issued token.
type IssuedToken struct {
	AccessToken string    `json:"accessToken"`
	ShareID     string    `json:"shareId"`
	ClientID    string    `json:"clientId"`
	IssuedAt    time.Time `json:"issuedAt"`
	ExpiresAt   time.Time `json:"expiresAt"`
}

// IsExpired returns true if the token has expired.
func (t *IssuedToken) IsExpired() bool {
	return time.Now().After(t.ExpiresAt)
}

// GenerateAccessToken creates a cryptographically secure access token.
func GenerateAccessToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
