// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// Package token implements OCM token exchange (OAuth-style).
package token

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
)

const DefaultTokenTTL = 1 * time.Hour //nolint:revive // exported: obvious default token TTL duration constant

type (
	TokenRequest  = spec.TokenRequest  //nolint:revive // exported: alias re-exporting spec.TokenRequest
	TokenResponse = spec.TokenResponse //nolint:revive // exported: alias re-exporting spec.TokenResponse
	OAuthError    = spec.OAuthError    //nolint:revive // exported: alias re-exporting spec.OAuthError
)

const (
	// GrantTypeAuthorizationCode is the authorization-code grant type.
	GrantTypeAuthorizationCode = spec.GrantTypeAuthorizationCode
	// ErrorInvalidRequest is the invalid-request OAuth error code.
	ErrorInvalidRequest = spec.ErrorInvalidRequest
	// ErrorInvalidGrant is the invalid-grant OAuth error code.
	ErrorInvalidGrant = spec.ErrorInvalidGrant
	// ErrorInvalidClient is the invalid-client OAuth error code.
	ErrorInvalidClient = spec.ErrorInvalidClient
	// ErrorUnauthorized is the unauthorized OAuth error code.
	ErrorUnauthorized = spec.ErrorUnauthorized
	// ErrorUnsupportedGrantType is the unsupported-grant-type OAuth error code.
	ErrorUnsupportedGrantType = spec.ErrorUnsupportedGrantType
	// ErrorServerError is the server-error OAuth error code.
	ErrorServerError = spec.ErrorServerError
)

// IssuedToken holds an access token issued by the OCM token endpoint.
type IssuedToken struct {
	AccessToken string    `json:"accessToken"`
	ShareID     string    `json:"shareId"`
	ClientID    string    `json:"clientId"`
	IssuedAt    time.Time `json:"issuedAt"`
	ExpiresAt   time.Time `json:"expiresAt"`
}

func (t *IssuedToken) IsExpired() bool { //nolint:revive // exported: trivial expiry check against ExpiresAt
	return time.Now().After(t.ExpiresAt)
}

// GenerateAccessToken returns a fresh 32-byte random hex access token.
func GenerateAccessToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("ocm: generate access token: %w", err)
	}

	return hex.EncodeToString(b), nil
}
