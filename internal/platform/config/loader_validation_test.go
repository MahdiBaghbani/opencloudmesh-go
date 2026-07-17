package config

import (
	"fmt"
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

func TestLoad_InvalidExternalBasePath_FailsFast(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
mode = "dev"
public_origin = "https://example.com"
external_base_path = "ocm"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error for invalid external_base_path")
	}
	if !strings.Contains(err.Error(), "external_base_path") {
		t.Errorf("expected external_base_path error, got: %v", err)
	}
}

// TestLoad_ValidEnumValues_Succeeds exercises enum values that remain
// reachable end-to-end. Every valid compatibility_scope ("none" or "scoped")
// requires signature inbound/outbound strict at the top level. Scoped forbids
// only peer_profile_level_override=all; tls.mode and outbound_http.ssrf.mode
// are not constrained by scoped guardrails.
func TestLoad_ValidEnumValues_Succeeds(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
mode = "compat"
compatibility_scope = "scoped"

[tls]
mode = "acme"

[outbound_http.ssrf]
mode = "off"

[signature]
peer_profile_level_override = "non-strict"
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
	if cfg.Signature.PeerProfileLevelOverride != "non-strict" {
		t.Errorf("expected peer_profile_level_override non-strict, got %s", cfg.Signature.PeerProfileLevelOverride)
	}
	if cfg.Signature.InboundMode != "strict" {
		t.Errorf("expected signature.inbound_mode strict, got %s", cfg.Signature.InboundMode)
	}
	if cfg.Signature.OutboundMode != "strict" {
		t.Errorf("expected signature.outbound_mode strict, got %s", cfg.Signature.OutboundMode)
	}
}

func TestLoad_RetiredSignatureInboundMode_FailsFast(t *testing.T) {
	for _, mode := range []string{"off", "lenient"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			configPath := filepath.Join(dir, "config.toml")
			content := fmt.Sprintf(`
mode = "dev"
public_origin = "https://example.com"

[signature]
inbound_mode = %q
outbound_mode = "strict"
`, mode)
			if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := Load(LoaderOptions{ConfigPath: configPath})
			if err == nil {
				t.Fatal("expected error for retired signature.inbound_mode")
			}
			if !strings.Contains(err.Error(), "invalid signature.inbound_mode") {
				t.Errorf("expected inbound_mode enum error, got: %v", err)
			}
		})
	}
}

func TestLoad_RetiredSignatureOutboundMode_FailsFast(t *testing.T) {
	for _, mode := range []string{"off", "token-only", "criteria-only"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			configPath := filepath.Join(dir, "config.toml")
			content := fmt.Sprintf(`
mode = "dev"
public_origin = "https://example.com"

[signature]
inbound_mode = "strict"
outbound_mode = %q
`, mode)
			if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := Load(LoaderOptions{ConfigPath: configPath})
			if err == nil {
				t.Fatal("expected error for retired signature.outbound_mode")
			}
			if !strings.Contains(err.Error(), "invalid signature.outbound_mode") {
				t.Errorf("expected outbound_mode enum error, got: %v", err)
			}
		})
	}
}
