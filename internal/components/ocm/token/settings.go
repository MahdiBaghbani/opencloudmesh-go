package token

import (
	"errors"
	"strings"
)

// TokenExchangeSettings holds validated token exchange configuration.
// Implements cfg.Setter for automatic ApplyDefaults() call.
type TokenExchangeSettings struct {
	Enabled bool   `mapstructure:"enabled"`
	Path    string `mapstructure:"path"`
}

// ApplyDefaults sets default values for unset fields.
// Called automatically by cfg.Decode() if this struct implements Setter.
func (s *TokenExchangeSettings) ApplyDefaults() {
	// Note: Enabled defaults are set at the config preset layer,
	// not here, because bool zero value (false) cannot distinguish
	// "unset" from "explicitly set to false".
	if s.Path == "" {
		s.Path = "token"
	}
}

// Validate checks configuration constraints.
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

// FullEndpoint returns the complete token endpoint URL.
func (s *TokenExchangeSettings) FullEndpoint(publicOrigin, externalBasePath string) string {
	base := publicOrigin + externalBasePath + "/ocm/"
	return base + s.Path
}

// RoutePath returns the path for Chi router mounting (relative to /ocm/).
func (s *TokenExchangeSettings) RoutePath() string {
	return "/" + s.Path
}
