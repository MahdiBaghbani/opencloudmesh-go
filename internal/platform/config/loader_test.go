package config

import (
	"strings"
	"testing"
)

func TestConfig_Redacted(t *testing.T) {
	cfg := &Config{
		Mode:         "strict",
		PublicOrigin: "https://example.com",
		Server: ServerConfig{
			TrustedProxies: []string{"127.0.0.0/8"},
			BootstrapAdmin: BootstrapAdminConfig{
				Username: "admin",
				Password: "supersecret",
			},
		},
		Signature: SignatureConfig{
			InboundMode:              "strict",
			OutboundMode:             "strict",
			PeerProfileLevelOverride: "non-strict",
			KeyPath:                  ".ocm/keys/signing.pem",
		},
		RequireTokenExchange: true,
	}

	redacted := cfg.Redacted()

	// Password should be redacted
	if strings.Contains(redacted, "supersecret") {
		t.Error("password was not redacted")
	}
	if !strings.Contains(redacted, "[REDACTED]") {
		t.Error("expected [REDACTED] placeholder")
	}
	// Username should be visible
	if !strings.Contains(redacted, "admin") {
		t.Error("username should be visible")
	}
	if !strings.Contains(redacted, "RequireTokenExchange: true") {
		t.Error("expected require_token_exchange in redacted output")
	}
	if strings.Contains(redacted, "WebDAVTokenExchange") {
		t.Error("expected WebDAVTokenExchange block removed from redacted output")
	}
}
