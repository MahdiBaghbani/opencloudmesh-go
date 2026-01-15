package webdav

// Settings holds WebDAV handler configuration.
// Implements cfg.Setter for automatic ApplyDefaults() call.
type Settings struct {
	// WebDAVTokenExchangeMode controls must-exchange-token enforcement.
	// Values: strict, lenient, off
	// - strict: always enforce must-exchange-token
	// - lenient: enforce with peer profile relaxations (behaves like strict until relaxations are implemented)
	// - off: never enforce must-exchange-token
	WebDAVTokenExchangeMode string `mapstructure:"webdav_token_exchange_mode"`
}

// ApplyDefaults sets default values for unset fields.
// Called automatically by cfg.Decode() if this struct implements Setter.
func (s *Settings) ApplyDefaults() {
	if s.WebDAVTokenExchangeMode == "" {
		s.WebDAVTokenExchangeMode = "strict"
	}
}

// EnforceMustExchangeToken returns true if must-exchange-token should be enforced.
// In strict and lenient modes, enforcement is enabled.
// In off mode, enforcement is disabled.
func (s *Settings) EnforceMustExchangeToken() bool {
	return s.WebDAVTokenExchangeMode != "off"
}
