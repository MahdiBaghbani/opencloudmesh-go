package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoad_UnknownKeys_Fail(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
mode = "dev"

[identity]
session_ttl_hours = 24

[fake_phantom_section]
some_future_key = true

[unknown_section]
random_key = "value"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("Load() should fail with unsupported keys")
	}
	if !strings.Contains(err.Error(), "unsupported keys") {
		t.Errorf("expected unsupported-keys error, got: %v", err)
	}
}

func TestLoad_InvalidTLSMode_FailsFast(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
[tls]
mode = "letsencrypt"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error for invalid tls.mode")
	}
	if !strings.Contains(err.Error(), "invalid tls.mode") {
		t.Errorf("expected tls.mode error, got: %v", err)
	}
}

func TestLoad_InvalidSignatureInboundMode_FailsFast(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
[signature]
inbound_mode = "relaxed"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error for invalid signature.inbound_mode")
	}
	if !strings.Contains(err.Error(), "invalid signature.inbound_mode") {
		t.Errorf("expected signature.inbound_mode error, got: %v", err)
	}
}

func TestLoad_InvalidSignatureOutboundMode_FailsFast(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
[signature]
outbound_mode = "relaxed"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error for invalid signature.outbound_mode")
	}
	if !strings.Contains(err.Error(), "invalid signature.outbound_mode") {
		t.Errorf("expected signature.outbound_mode error, got: %v", err)
	}
}

func TestLoad_UnsupportedAdvertiseHTTPSignaturesKey_Fails(t *testing.T) {
	tests := []struct {
		name   string
		config string
	}{
		{
			name: "nested in signature table",
			config: `
mode = "compat"
[signature]
advertise_http_request_signatures = true
`,
		},
		{
			name: "dotted root key",
			config: `
mode = "compat"
signature.advertise_http_request_signatures = true
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			configPath := filepath.Join(dir, "config.toml")

			if err := os.WriteFile(configPath, []byte(tt.config), 0644); err != nil {
				t.Fatalf("failed to write config: %v", err)
			}

			_, err := Load(LoaderOptions{ConfigPath: configPath})
			if err == nil {
				t.Fatal("expected error for unsupported key")
			}
			if !strings.Contains(err.Error(), "advertise_http_request_signatures") {
				t.Errorf("expected error mentioning advertise_http_request_signatures, got: %v", err)
			}
		})
	}
}

func TestLoad_InvalidOnDiscoveryError_FailsFast(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
[signature]
on_discovery_error = "ignore"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error for invalid signature.on_discovery_error")
	}
	if !strings.Contains(err.Error(), "invalid signature.on_discovery_error") {
		t.Errorf("expected on_discovery_error error, got: %v", err)
	}
}

func TestLoad_ValidEnumValues_Succeeds(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	// Test valid enum combinations.
	tomlContent := `
mode = "compat"

[tls]
mode = "acme"

[outbound_http.ssrf]
mode = "off"

[signature]
inbound_mode = "lenient"
outbound_mode = "criteria-only"
peer_profile_level_override = "all"
on_discovery_error = "allow"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.TLS.Mode != "acme" {
		t.Errorf("expected tls.mode acme, got %s", cfg.TLS.Mode)
	}
	if cfg.OutboundHTTP.SSRF.Mode != "off" {
		t.Errorf("expected ssrf.mode off, got %s", cfg.OutboundHTTP.SSRF.Mode)
	}
	if cfg.Signature.InboundMode != "lenient" {
		t.Errorf("expected signature.inbound_mode lenient, got %s", cfg.Signature.InboundMode)
	}
	if cfg.Signature.OutboundMode != "criteria-only" {
		t.Errorf("expected signature.outbound_mode criteria-only, got %s", cfg.Signature.OutboundMode)
	}
	if cfg.Signature.PeerProfileLevelOverride != "all" {
		t.Errorf("expected peer_profile_level_override all, got %s", cfg.Signature.PeerProfileLevelOverride)
	}
	if cfg.Signature.OnDiscoveryError != "allow" {
		t.Errorf("expected on_discovery_error allow, got %s", cfg.Signature.OnDiscoveryError)
	}
}
