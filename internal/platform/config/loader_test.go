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

func TestLoad_StrictModeSignatureIETFDefaults(t *testing.T) {
	cfg, err := Load(LoaderOptions{ModeFlag: "strict"})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Signature.Label != DefaultSignatureLabel {
		t.Fatalf("Label = %q, want %q", cfg.Signature.Label, DefaultSignatureLabel)
	}
	if cfg.Signature.InboundMode != "strict" {
		t.Fatalf("InboundMode = %q, want strict", cfg.Signature.InboundMode)
	}
	if cfg.Signature.OutboundMode != "strict" {
		t.Fatalf("OutboundMode = %q, want strict", cfg.Signature.OutboundMode)
	}
	if len(cfg.Signature.AllowedAlgorithms) != 1 || cfg.Signature.AllowedAlgorithms[0] != "ed25519" {
		t.Fatalf("AllowedAlgorithms = %v", cfg.Signature.AllowedAlgorithms)
	}
}
