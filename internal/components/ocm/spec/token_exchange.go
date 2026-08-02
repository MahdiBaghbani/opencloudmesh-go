// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package spec

// TokenRequest represents an incoming token exchange request (form-urlencoded).
type TokenRequest struct {
	GrantType string `json:"grant_type"` //nolint:tagliatelle // RFC 6749 mandates snake_case for OAuth 2.0 token endpoint fields
	ClientID  string `json:"client_id"`  //nolint:tagliatelle // RFC 6749 mandates snake_case for OAuth 2.0 token endpoint fields
	Code      string `json:"code"`
}

// TokenResponse represents a successful token exchange response.
type TokenResponse struct {
	AccessToken string `json:"access_token"` //nolint:tagliatelle // RFC 6749 mandates snake_case for OAuth 2.0 token endpoint fields
	TokenType   string `json:"token_type"`   //nolint:tagliatelle // RFC 6749 mandates snake_case for OAuth 2.0 token endpoint fields
	ExpiresIn   int    `json:"expires_in"`   //nolint:tagliatelle // RFC 6749 mandates snake_case for OAuth 2.0 token endpoint fields
}

// OAuthError represents an OAuth-style error response.
type OAuthError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"` //nolint:tagliatelle // RFC 6749 mandates snake_case for OAuth 2.0 token endpoint fields
}

// GrantType constants.
const (
	GrantTypeAuthorizationCode = "authorization_code"
)

// OAuth error codes.
const (
	ErrorInvalidRequest       = "invalid_request"
	ErrorInvalidGrant         = "invalid_grant"
	ErrorInvalidClient        = "invalid_client"
	ErrorUnauthorized         = "unauthorized_client"
	ErrorUnsupportedGrantType = "unsupported_grant_type"
)
