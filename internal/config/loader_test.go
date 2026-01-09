package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseMode(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    Mode
		wantErr bool
	}{
		{"strict", "strict", ModeStrict, false},
		{"interop", "interop", ModeInterop, false},
		{"dev", "dev", ModeDev, false},
		{"empty defaults to strict", "", ModeStrict, false},
		{"uppercase", "STRICT", ModeStrict, false},
		{"mixed case", "Interop", ModeInterop, false},
		{"whitespace", "  dev  ", ModeDev, false},
		{"invalid", "invalid", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseMode(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseMode(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ParseMode(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestLoad_NoConfigFile(t *testing.T) {
	// Without a config file, defaults to strict mode
	cfg, err := Load(LoaderOptions{})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Mode != "strict" {
		t.Errorf("expected mode strict, got %s", cfg.Mode)
	}
	if cfg.OutboundHTTP.SSRFMode != "strict" {
		t.Errorf("expected SSRF mode strict, got %s", cfg.OutboundHTTP.SSRFMode)
	}
	if cfg.Signature.Mode != "strict" {
		t.Errorf("expected signature mode strict, got %s", cfg.Signature.Mode)
	}
}

func TestLoad_ModeFlag(t *testing.T) {
	// Mode flag overrides default
	cfg, err := Load(LoaderOptions{ModeFlag: "dev"})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Mode != "dev" {
		t.Errorf("expected mode dev, got %s", cfg.Mode)
	}
	if cfg.OutboundHTTP.SSRFMode != "off" {
		t.Errorf("expected SSRF mode off in dev, got %s", cfg.OutboundHTTP.SSRFMode)
	}
	if cfg.OutboundHTTP.InsecureSkipVerify != true {
		t.Errorf("expected InsecureSkipVerify true in dev")
	}
}

func TestLoad_ConfigFile(t *testing.T) {
	// Create a temp TOML config file
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
mode = "interop"
external_origin = "https://example.com:8443"
listen_addr = ":8443"

[server]
trusted_proxies = ["10.0.0.0/8"]

[server.bootstrap_admin]
username = "root"
password = "secret123"

[outbound_http]
ssrf_mode = "strict"
timeout_ms = 5000
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Mode != "interop" {
		t.Errorf("expected mode interop, got %s", cfg.Mode)
	}
	if cfg.ExternalOrigin != "https://example.com:8443" {
		t.Errorf("expected origin https://example.com:8443, got %s", cfg.ExternalOrigin)
	}
	if cfg.ListenAddr != ":8443" {
		t.Errorf("expected listen :8443, got %s", cfg.ListenAddr)
	}
	if len(cfg.Server.TrustedProxies) != 1 || cfg.Server.TrustedProxies[0] != "10.0.0.0/8" {
		t.Errorf("expected trusted proxies [10.0.0.0/8], got %v", cfg.Server.TrustedProxies)
	}
	if cfg.Server.BootstrapAdmin.Username != "root" {
		t.Errorf("expected admin username root, got %s", cfg.Server.BootstrapAdmin.Username)
	}
	if cfg.Server.BootstrapAdmin.Password != "secret123" {
		t.Errorf("expected admin password secret123, got %s", cfg.Server.BootstrapAdmin.Password)
	}
	// TOML overrides mode preset
	if cfg.OutboundHTTP.SSRFMode != "strict" {
		t.Errorf("expected SSRF mode strict from TOML, got %s", cfg.OutboundHTTP.SSRFMode)
	}
	if cfg.OutboundHTTP.TimeoutMS != 5000 {
		t.Errorf("expected timeout 5000, got %d", cfg.OutboundHTTP.TimeoutMS)
	}
}

func TestLoad_Precedence_FlagsOverrideConfigFile(t *testing.T) {
	// Create a TOML config file
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
external_origin = "https://from-toml.com"
listen_addr = ":9000"

[signature]
mode = "lenient"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	// Flags should override TOML
	origin := "https://from-flag.com"
	sigPolicy := "strict"
	cfg, err := Load(LoaderOptions{
		ConfigPath: configPath,
		FlagOverrides: FlagOverrides{
			ExternalOrigin:  &origin,
			SignaturePolicy: &sigPolicy,
		},
	})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.ExternalOrigin != "https://from-flag.com" {
		t.Errorf("expected origin from flag, got %s", cfg.ExternalOrigin)
	}
	if cfg.ListenAddr != ":9000" {
		t.Errorf("expected listen from TOML :9000, got %s", cfg.ListenAddr)
	}
	if cfg.Signature.Mode != "strict" {
		t.Errorf("expected signature mode from flag strict, got %s", cfg.Signature.Mode)
	}
}

func TestLoad_ModeFlag_OverridesConfigFileMode(t *testing.T) {
	// Create a TOML config file with mode
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
mode = "interop"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	// Mode flag should override TOML mode
	cfg, err := Load(LoaderOptions{
		ConfigPath: configPath,
		ModeFlag:   "dev",
	})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Mode != "dev" {
		t.Errorf("expected mode dev from flag, got %s", cfg.Mode)
	}
	// Dev preset defaults should apply
	if cfg.OutboundHTTP.SSRFMode != "off" {
		t.Errorf("expected SSRF mode off from dev preset, got %s", cfg.OutboundHTTP.SSRFMode)
	}
}

func TestLoad_MissingConfigFile_FailsFast(t *testing.T) {
	_, err := Load(LoaderOptions{ConfigPath: "/nonexistent/path/config.toml"})
	if err == nil {
		t.Fatal("expected error for missing config file")
	}
	if !strings.Contains(err.Error(), "failed to read config file") {
		t.Errorf("expected read error, got: %v", err)
	}
}

func TestLoad_InvalidTOML_FailsFast(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	// Invalid TOML
	if err := os.WriteFile(configPath, []byte("this is not valid toml [[["), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error for invalid TOML")
	}
	if !strings.Contains(err.Error(), "failed to parse config file") {
		t.Errorf("expected parse error, got: %v", err)
	}
}

func TestLoad_InvalidMode_FailsFast(t *testing.T) {
	_, err := Load(LoaderOptions{ModeFlag: "invalid"})
	if err == nil {
		t.Fatal("expected error for invalid mode")
	}
	if !strings.Contains(err.Error(), "invalid mode") {
		t.Errorf("expected mode error, got: %v", err)
	}
}

func TestStrictConfig(t *testing.T) {
	cfg := StrictConfig()

	if cfg.Mode != "strict" {
		t.Errorf("expected mode strict, got %s", cfg.Mode)
	}
	if cfg.OutboundHTTP.SSRFMode != "strict" {
		t.Errorf("expected SSRF mode strict, got %s", cfg.OutboundHTTP.SSRFMode)
	}
	if cfg.Signature.Mode != "strict" {
		t.Errorf("expected signature mode strict, got %s", cfg.Signature.Mode)
	}
	if cfg.OutboundHTTP.InsecureSkipVerify {
		t.Error("expected InsecureSkipVerify false in strict")
	}
	if cfg.OutboundHTTP.MaxRedirects != 1 {
		t.Errorf("expected MaxRedirects 1 in strict, got %d", cfg.OutboundHTTP.MaxRedirects)
	}
}

func TestDevConfig(t *testing.T) {
	cfg := DevConfig()

	if cfg.Mode != "dev" {
		t.Errorf("expected mode dev, got %s", cfg.Mode)
	}
	if cfg.OutboundHTTP.SSRFMode != "off" {
		t.Errorf("expected SSRF mode off, got %s", cfg.OutboundHTTP.SSRFMode)
	}
	if cfg.TLS.Mode != "off" {
		t.Errorf("expected TLS mode off, got %s", cfg.TLS.Mode)
	}
	if !cfg.OutboundHTTP.InsecureSkipVerify {
		t.Error("expected InsecureSkipVerify true in dev")
	}
}

func TestInteropConfig(t *testing.T) {
	cfg := InteropConfig()

	if cfg.Mode != "interop" {
		t.Errorf("expected mode interop, got %s", cfg.Mode)
	}
	if cfg.Signature.Mode != "lenient" {
		t.Errorf("expected signature mode lenient, got %s", cfg.Signature.Mode)
	}
	// SSRF stays strict in interop
	if cfg.OutboundHTTP.SSRFMode != "strict" {
		t.Errorf("expected SSRF mode strict in interop, got %s", cfg.OutboundHTTP.SSRFMode)
	}
}

func TestConfig_Redacted(t *testing.T) {
	cfg := &Config{
		Mode:           "strict",
		ExternalOrigin: "https://example.com",
		Server: ServerConfig{
			TrustedProxies: []string{"127.0.0.0/8"},
			BootstrapAdmin: BootstrapAdminConfig{
				Username: "admin",
				Password: "supersecret",
			},
		},
		Signature: SignatureConfig{
			Mode:    "strict",
			KeyPath: ".ocm/keys/signing.pem",
		},
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
}

func TestLoad_UndecodedKeys_WarnsButSucceeds(t *testing.T) {
	// Create a TOML config with undecoded keys
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
mode = "dev"

[identity]
session_ttl_hours = 24

[token_exchange]
enabled = true

[unknown_section]
random_key = "value"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	// Load should succeed despite undecoded keys
	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() should succeed with undecoded keys, got error: %v", err)
	}

	// Verify the decoded mode was applied
	if cfg.Mode != "dev" {
		t.Errorf("expected mode dev, got %s", cfg.Mode)
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

func TestLoad_InvalidSSRFMode_FailsFast(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
[outbound_http]
ssrf_mode = "block"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error for invalid outbound_http.ssrf_mode")
	}
	if !strings.Contains(err.Error(), "invalid outbound_http.ssrf_mode") {
		t.Errorf("expected ssrf_mode error, got: %v", err)
	}
}

func TestLoad_InvalidSignatureMode_FailsFast(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
[signature]
mode = "relaxed"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error for invalid signature.mode")
	}
	if !strings.Contains(err.Error(), "invalid signature.mode") {
		t.Errorf("expected signature.mode error, got: %v", err)
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

	// Test all valid enum combinations
	tomlContent := `
mode = "strict"

[tls]
mode = "acme"

[outbound_http]
ssrf_mode = "off"

[signature]
mode = "lenient"
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
	if cfg.OutboundHTTP.SSRFMode != "off" {
		t.Errorf("expected ssrf_mode off, got %s", cfg.OutboundHTTP.SSRFMode)
	}
	if cfg.Signature.Mode != "lenient" {
		t.Errorf("expected signature.mode lenient, got %s", cfg.Signature.Mode)
	}
	if cfg.Signature.OnDiscoveryError != "allow" {
		t.Errorf("expected on_discovery_error allow, got %s", cfg.Signature.OnDiscoveryError)
	}
}

func TestLoad_CacheDriverDefaultsToMemory(t *testing.T) {
	// Without a cache section, cache.driver should be empty (will default to memory at runtime)
	cfg, err := Load(LoaderOptions{})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// Empty driver is valid and will be treated as "memory" at runtime
	if cfg.Cache.Driver != "" {
		t.Errorf("expected empty cache.driver by default, got %q", cfg.Cache.Driver)
	}
}

func TestLoad_CacheDriverMemoryValid(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "config-cache-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	configPath := filepath.Join(tempDir, "config.toml")
	tomlContent := `
mode = "strict"

[cache]
driver = "memory"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Cache.Driver != "memory" {
		t.Errorf("expected cache.driver memory, got %q", cfg.Cache.Driver)
	}
}

func TestLoad_CacheDriverUnknownFails(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "config-cache-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	configPath := filepath.Join(tempDir, "config.toml")
	tomlContent := `
mode = "strict"

[cache]
driver = "redis"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err = Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error for unknown cache driver")
	}
	if !strings.Contains(err.Error(), "cache.driver") {
		t.Errorf("expected error to mention cache.driver, got: %v", err)
	}
	if !strings.Contains(err.Error(), "memory") {
		t.Errorf("expected error to mention memory as only supported driver, got: %v", err)
	}
}

func TestLoad_FederationEnabledNoConfigPathsFails(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "config-fed-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	configPath := filepath.Join(tempDir, "config.toml")
	tomlContent := `
mode = "strict"

[federation]
enabled = true
config_paths = []
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err = Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error for federation enabled with no config_paths")
	}
	if !strings.Contains(err.Error(), "config_paths must be non-empty") {
		t.Errorf("expected error about non-empty config_paths, got: %v", err)
	}
}

func TestLoad_FederationEnabledNonExistentPathFails(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "config-fed-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	configPath := filepath.Join(tempDir, "config.toml")
	tomlContent := `
mode = "strict"

[federation]
enabled = true
config_paths = ["/nonexistent/path/federation.json"]
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err = Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error for non-existent federation config path")
	}
	if !strings.Contains(err.Error(), "not readable") {
		t.Errorf("expected error about readable path, got: %v", err)
	}
}

func TestLoad_FederationEnabledValidPathSucceeds(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "config-fed-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a valid (empty) federation config file
	fedPath := filepath.Join(tempDir, "federation.json")
	if err := os.WriteFile(fedPath, []byte(`{"federation_id":"test"}`), 0644); err != nil {
		t.Fatalf("failed to write federation config: %v", err)
	}

	configPath := filepath.Join(tempDir, "config.toml")
	tomlContent := `
mode = "strict"

[federation]
enabled = true
config_paths = ["` + fedPath + `"]
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if !cfg.Federation.Enabled {
		t.Error("expected federation to be enabled")
	}
	if len(cfg.Federation.ConfigPaths) != 1 {
		t.Errorf("expected 1 config path, got %d", len(cfg.Federation.ConfigPaths))
	}
}

func TestLoad_FederationDisabledNeedsNoConfigPaths(t *testing.T) {
	// Federation disabled should not require config_paths
	tempDir, err := os.MkdirTemp("", "config-fed-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	configPath := filepath.Join(tempDir, "config.toml")
	tomlContent := `
mode = "strict"

[federation]
enabled = false
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Federation.Enabled {
		t.Error("expected federation to be disabled")
	}
}
