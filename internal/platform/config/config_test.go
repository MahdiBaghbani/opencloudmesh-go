package config

import "testing"

// TestSchemeFromOrigin documents the empty-on-invalid contract used by call
// sites that must leave localScheme empty when PublicOrigin is empty or
// unparseable (invites, notifications, signature middleware).
func TestSchemeFromOrigin(t *testing.T) {
	tests := []struct {
		name   string
		origin string
		want   string
	}{
		{"empty origin returns empty", "", ""},
		{"missing scheme returns empty", "example.com", ""},
		{"unparseable origin returns empty", "://bad", ""},
		{"https preserved", "https://example.com", "https"},
		{"http preserved", "http://example.com:8080", "http"},
		{"uppercase scheme lowercased", "HTTPS://example.com", "https"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SchemeFromOrigin(tt.origin); got != tt.want {
				t.Errorf("SchemeFromOrigin(%q) = %q, want %q", tt.origin, got, tt.want)
			}
		})
	}
}

// TestPublicSchemeFromOrigin documents the https-default contract retained for
// config-aware callers and the token handler.
func TestPublicSchemeFromOrigin(t *testing.T) {
	tests := []struct {
		name   string
		origin string
		want   string
	}{
		{"empty origin defaults to https", "", "https"},
		{"missing scheme defaults to https", "example.com", "https"},
		{"unparseable origin defaults to https", "://bad", "https"},
		{"https preserved", "https://example.com", "https"},
		{"http preserved", "http://example.com:8080", "http"},
		{"uppercase scheme lowercased", "HTTP://example.com", "http"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := PublicSchemeFromOrigin(tt.origin); got != tt.want {
				t.Errorf("PublicSchemeFromOrigin(%q) = %q, want %q", tt.origin, got, tt.want)
			}
		})
	}
}

// TestConfigPublicScheme confirms the config-aware method keeps the https
// default for an empty PublicOrigin.
func TestConfigPublicScheme(t *testing.T) {
	if got := (&Config{}).PublicScheme(); got != "https" {
		t.Errorf("(&Config{}).PublicScheme() = %q, want %q", got, "https")
	}
	if got := (&Config{PublicOrigin: "http://example.com"}).PublicScheme(); got != "http" {
		t.Errorf("PublicScheme() = %q, want %q", got, "http")
	}
}
