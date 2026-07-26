package incoming

import (
	"errors"
	"strings"
)

// TokenExchangeSettings holds token exchange config. Implements cfg.Setter for ApplyDefaults().
type TokenExchangeSettings struct {
	Path string `mapstructure:"path"`
}

// ApplyDefaults sets default values. Called by cfg.Decode().
func (s *TokenExchangeSettings) ApplyDefaults() {
	if s.Path == "" {
		s.Path = "token"
	}
}

// Validate enforces path constraints.
func (s *TokenExchangeSettings) Validate() error {
	if strings.TrimSpace(s.Path) == "" {
		return errors.New("token_exchange.path must not be empty")
	}

	if strings.Contains(s.Path, "..") {
		return errors.New("token_exchange.path must not contain '..'")
	}

	if strings.HasPrefix(s.Path, "/") {
		return errors.New("token_exchange.path must be relative (no leading slash)")
	}

	if strings.Contains(s.Path, "://") {
		return errors.New("token_exchange.path must not contain a scheme")
	}

	return nil
}

// FullEndpoint returns the full token URL (publicOrigin + basePath + /ocm/ + path).
func (s *TokenExchangeSettings) FullEndpoint(publicOrigin, externalBasePath string) string {
	base := publicOrigin + externalBasePath + "/ocm/"
	return base + s.Path
}

// RoutePath returns the Chi route path (relative to /ocm/).
func (s *TokenExchangeSettings) RoutePath() string {
	return "/" + s.Path
}
