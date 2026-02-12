// Package token implements OCM token exchange (OAuth-style).
package token

import (
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
)

const DefaultTokenTTL = 1 * time.Hour

type (
	TokenRequest  = spec.TokenRequest
	TokenResponse = spec.TokenResponse
	OAuthError    = spec.OAuthError
)

const (
	GrantTypeAuthorizationCode = spec.GrantTypeAuthorizationCode
	GrantTypeOCMShare          = spec.GrantTypeOCMShare
	ErrorInvalidRequest = spec.ErrorInvalidRequest
	ErrorInvalidGrant   = spec.ErrorInvalidGrant
	ErrorInvalidClient  = spec.ErrorInvalidClient
	ErrorUnauthorized   = spec.ErrorUnauthorized
)

type IssuedToken struct {
	AccessToken string    `json:"accessToken"`
	ShareID     string    `json:"shareId"`
	ClientID    string    `json:"clientId"`
	IssuedAt    time.Time `json:"issuedAt"`
	ExpiresAt   time.Time `json:"expiresAt"`
}

func (t *IssuedToken) IsExpired() bool {
	return time.Now().After(t.ExpiresAt)
}

func GenerateAccessToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
