// Package token implements OCM token exchange (OAuth-style).
package token

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

// DefaultTokenTTL is the default time-to-live for access tokens.
const DefaultTokenTTL = 1 * time.Hour

// TokenRequest represents an incoming token exchange request.
// Supports both form-urlencoded (spec) and JSON (Nextcloud interop).
type TokenRequest struct {
	GrantType string `json:"grant_type"`
	ClientID  string `json:"client_id"`
	Code      string `json:"code"`
}

// TokenResponse represents a successful token exchange response.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// OAuthError represents an OAuth-style error response.
type OAuthError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// GrantType constants.
const (
	GrantTypeOCMShare = "ocm_share"
)

// OAuth error codes.
const (
	ErrorInvalidRequest = "invalid_request"
	ErrorInvalidGrant   = "invalid_grant"
	ErrorInvalidClient  = "invalid_client"
	ErrorUnauthorized   = "unauthorized_client"
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
