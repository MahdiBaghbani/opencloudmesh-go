package webdav

// Settings holds WebDAV configuration. Implements cfg.Setter for ApplyDefaults().
type Settings struct {
	// WebDAVTokenExchangeMode: strict (always enforce), lenient (peer relaxations), off (never enforce).
	WebDAVTokenExchangeMode string `mapstructure:"webdav_token_exchange_mode"`
}

// ApplyDefaults sets defaults. Called by cfg.Decode().
func (s *Settings) ApplyDefaults() {
	if s.WebDAVTokenExchangeMode == "" {
		s.WebDAVTokenExchangeMode = "strict"
	}
}

// EnforceMustExchangeToken reports whether to enforce must-exchange-token (strict/lenient yes, off no).
func (s *Settings) EnforceMustExchangeToken() bool {
	return s.WebDAVTokenExchangeMode != "off"
}
