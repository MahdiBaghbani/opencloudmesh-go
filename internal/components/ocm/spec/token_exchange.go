package spec

// TokenRequest represents an incoming token exchange request (form-urlencoded).
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
