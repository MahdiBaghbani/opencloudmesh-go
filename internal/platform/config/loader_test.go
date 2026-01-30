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
	if cfg.Signature.InboundMode != "strict" {
		t.Errorf("expected signature inbound mode strict, got %s", cfg.Signature.InboundMode)
	}
	if cfg.Signature.OutboundMode != "strict" {
		t.Errorf("expected signature outbound mode strict, got %s", cfg.Signature.OutboundMode)
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
public_origin = "https://example.com:8443"
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
	if cfg.PublicOrigin != "https://example.com:8443" {
		t.Errorf("expected origin https://example.com:8443, got %s", cfg.PublicOrigin)
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
public_origin = "https://from-toml.com"
listen_addr = ":9000"

[signature]
inbound_mode = "lenient"
outbound_mode = "criteria-only"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	// Flags should override TOML
	origin := "https://from-flag.com"
	sigInbound := "strict"
	cfg, err := Load(LoaderOptions{
		ConfigPath: configPath,
		FlagOverrides: FlagOverrides{
			PublicOrigin:       &origin,
			SignatureInboundMode: &sigInbound,
		},
	})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.PublicOrigin != "https://from-flag.com" {
		t.Errorf("expected origin from flag, got %s", cfg.PublicOrigin)
	}
	if cfg.ListenAddr != ":9000" {
		t.Errorf("expected listen from TOML :9000, got %s", cfg.ListenAddr)
	}
	if cfg.Signature.InboundMode != "strict" {
		t.Errorf("expected signature inbound mode from flag strict, got %s", cfg.Signature.InboundMode)
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
	if cfg.Signature.InboundMode != "strict" {
		t.Errorf("expected signature inbound mode strict, got %s", cfg.Signature.InboundMode)
	}
	if cfg.Signature.OutboundMode != "strict" {
		t.Errorf("expected signature outbound mode strict, got %s", cfg.Signature.OutboundMode)
	}
	if !cfg.Signature.AdvertiseHTTPRequestSignatures {
		t.Error("expected advertise_http_request_signatures true in strict")
	}
	if cfg.Signature.PeerProfileLevelOverride != "non-strict" {
		t.Errorf("expected peer_profile_level_override non-strict, got %s", cfg.Signature.PeerProfileLevelOverride)
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
	if cfg.Signature.InboundMode != "lenient" {
		t.Errorf("expected signature inbound mode lenient, got %s", cfg.Signature.InboundMode)
	}
	if cfg.Signature.OutboundMode != "criteria-only" {
		t.Errorf("expected signature outbound mode criteria-only, got %s", cfg.Signature.OutboundMode)
	}
	if !cfg.Signature.AdvertiseHTTPRequestSignatures {
		t.Error("expected advertise_http_request_signatures true in interop")
	}
	// SSRF stays strict in interop
	if cfg.OutboundHTTP.SSRFMode != "strict" {
		t.Errorf("expected SSRF mode strict in interop, got %s", cfg.OutboundHTTP.SSRFMode)
	}
}

func TestConfig_Redacted(t *testing.T) {
	cfg := &Config{
		Mode:           "strict",
		PublicOrigin: "https://example.com",
		Server: ServerConfig{
			TrustedProxies: []string{"127.0.0.0/8"},
			BootstrapAdmin: BootstrapAdminConfig{
				Username: "admin",
				Password: "supersecret",
			},
		},
		Signature: SignatureConfig{
			InboundMode:                    "strict",
			OutboundMode:                   "strict",
			AdvertiseHTTPRequestSignatures: true,
			PeerProfileLevelOverride:       "non-strict",
			KeyPath:                        ".ocm/keys/signing.pem",
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

[fake_phantom_section]
some_future_key = true

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

func TestLoad_AdvertiseGuardrail_InboundOffRejectsAdvertiseTrue(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
[signature]
inbound_mode = "off"
outbound_mode = "off"
advertise_http_request_signatures = true
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error for advertise=true when inbound_mode=off")
	}
	if !strings.Contains(err.Error(), "advertise_http_request_signatures cannot be true") {
		t.Errorf("expected guardrail error, got: %v", err)
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
	if cfg.OutboundHTTP.SSRFMode != "off" {
		t.Errorf("expected ssrf_mode off, got %s", cfg.OutboundHTTP.SSRFMode)
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

func TestLoad_CacheDriverRedisValid(t *testing.T) {
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

	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Cache.Driver != "redis" {
		t.Errorf("expected cache.driver redis, got %q", cfg.Cache.Driver)
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
driver = "unknown"
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
	if !strings.Contains(err.Error(), "memory") || !strings.Contains(err.Error(), "redis") {
		t.Errorf("expected error to mention memory and redis as supported drivers, got: %v", err)
	}
}

func TestLoad_PeerTrustEnabledNoConfigPathsFails(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "config-fed-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	configPath := filepath.Join(tempDir, "config.toml")
	tomlContent := `
mode = "strict"

[peer_trust]
enabled = true
config_paths = []
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err = Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error for peer trust enabled with no config_paths")
	}
	if !strings.Contains(err.Error(), "config_paths must be non-empty") {
		t.Errorf("expected error about non-empty config_paths, got: %v", err)
	}
}

func TestLoad_PeerTrustEnabledNonExistentPathFails(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "config-fed-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	configPath := filepath.Join(tempDir, "config.toml")
	tomlContent := `
mode = "strict"

[peer_trust]
enabled = true
config_paths = ["/nonexistent/path/trust-group.json"]
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err = Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error for non-existent peer trust config path")
	}
	if !strings.Contains(err.Error(), "not readable") {
		t.Errorf("expected error about readable path, got: %v", err)
	}
}

func TestLoad_PeerTrustEnabledValidPathSucceeds(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "config-fed-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a valid trust group config file
	tgPath := filepath.Join(tempDir, "trust-group.json")
	if err := os.WriteFile(tgPath, []byte(`{"trust_group_id":"test"}`), 0644); err != nil {
		t.Fatalf("failed to write trust group config: %v", err)
	}

	configPath := filepath.Join(tempDir, "config.toml")
	tomlContent := `
mode = "strict"

[peer_trust]
enabled = true
config_paths = ["` + tgPath + `"]
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if !cfg.PeerTrust.Enabled {
		t.Error("expected peer trust to be enabled")
	}
	if len(cfg.PeerTrust.ConfigPaths) != 1 {
		t.Errorf("expected 1 config path, got %d", len(cfg.PeerTrust.ConfigPaths))
	}
}

func TestLoad_PeerTrustDisabledNeedsNoConfigPaths(t *testing.T) {
	// Peer trust disabled should not require config_paths
	tempDir, err := os.MkdirTemp("", "config-fed-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	configPath := filepath.Join(tempDir, "config.toml")
	tomlContent := `
mode = "strict"

[peer_trust]
enabled = false
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.PeerTrust.Enabled {
		t.Error("expected peer trust to be disabled")
	}
}

func TestLoad_FederationTOMLStrictBreak(t *testing.T) {
	// The old [federation] TOML section must be rejected with a clear migration message.
	tempDir, err := os.MkdirTemp("", "config-fed-strict-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	configPath := filepath.Join(tempDir, "config.toml")
	tomlContent := `
mode = "strict"

[federation]
enabled = true
config_paths = ["/some/path.json"]
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err = Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error for deprecated [federation] TOML section")
	}
	if !strings.Contains(err.Error(), "has been renamed to '[peer_trust]'") {
		t.Errorf("expected strict-break migration message, got: %v", err)
	}
}

func TestLoad_FederationDottedKeyStrictBreak(t *testing.T) {
	// Even individual federation.* keys (not a full table) must be rejected.
	tempDir, err := os.MkdirTemp("", "config-fed-strict-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	configPath := filepath.Join(tempDir, "config.toml")
	tomlContent := `
mode = "strict"
federation.enabled = true
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err = Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error for deprecated federation.enabled dotted key")
	}
	if !strings.Contains(err.Error(), "has been renamed to '[peer_trust]'") {
		t.Errorf("expected strict-break migration message, got: %v", err)
	}
}

func TestLoggingConfig_DefaultsPerMode(t *testing.T) {
	// Strict mode defaults to info level
	strictCfg := StrictConfig()
	if strictCfg.Logging.Level != "info" {
		t.Errorf("expected strict mode logging.level 'info', got %q", strictCfg.Logging.Level)
	}
	if strictCfg.Logging.AllowSensitive {
		t.Error("expected strict mode logging.allow_sensitive false")
	}

	// Interop mode defaults to info level
	interopCfg := InteropConfig()
	if interopCfg.Logging.Level != "info" {
		t.Errorf("expected interop mode logging.level 'info', got %q", interopCfg.Logging.Level)
	}
	if interopCfg.Logging.AllowSensitive {
		t.Error("expected interop mode logging.allow_sensitive false")
	}

	// Dev mode defaults to debug level
	devCfg := DevConfig()
	if devCfg.Logging.Level != "debug" {
		t.Errorf("expected dev mode logging.level 'debug', got %q", devCfg.Logging.Level)
	}
	if devCfg.Logging.AllowSensitive {
		t.Error("expected dev mode logging.allow_sensitive false")
	}
}

func TestLoad_LoggingConfig_FromTOML(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
mode = "strict"

[logging]
level = "warn"
allow_sensitive = true
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Logging.Level != "warn" {
		t.Errorf("expected logging.level 'warn', got %q", cfg.Logging.Level)
	}
	if !cfg.Logging.AllowSensitive {
		t.Error("expected logging.allow_sensitive true from TOML")
	}
}

func TestLoad_LoggingConfig_FlagsOverrideTOML(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
mode = "strict"

[logging]
level = "warn"
allow_sensitive = true
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	logLevel := "error"
	allowSensitive := "false"
	cfg, err := Load(LoaderOptions{
		ConfigPath: configPath,
		FlagOverrides: FlagOverrides{
			LoggingLevel:          &logLevel,
			LoggingAllowSensitive: &allowSensitive,
		},
	})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Logging.Level != "error" {
		t.Errorf("expected logging.level 'error' from flag, got %q", cfg.Logging.Level)
	}
	if cfg.Logging.AllowSensitive {
		t.Error("expected logging.allow_sensitive false from flag")
	}
}

func TestLoad_LoggingConfig_InvalidLevel_FailsFast(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
mode = "strict"

[logging]
level = "verbose"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error for invalid logging.level")
	}
	if !strings.Contains(err.Error(), "invalid logging.level") {
		t.Errorf("expected logging.level error, got: %v", err)
	}
}

func TestLoad_LoggingConfig_AllValidLevels(t *testing.T) {
	validLevels := []string{"trace", "debug", "info", "warn", "error"}

	for _, level := range validLevels {
		t.Run(level, func(t *testing.T) {
			dir := t.TempDir()
			configPath := filepath.Join(dir, "config.toml")

			tomlContent := `
mode = "strict"

[logging]
level = "` + level + `"
`
			if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
				t.Fatalf("failed to write config: %v", err)
			}

			cfg, err := Load(LoaderOptions{ConfigPath: configPath})
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}

			if cfg.Logging.Level != level {
				t.Errorf("expected logging.level %q, got %q", level, cfg.Logging.Level)
			}
		})
	}
}

func TestTokenExchangeConfig_DefaultsPerMode(t *testing.T) {
	// Strict mode: enabled=true, path=token, webdav_mode=strict
	strictCfg := StrictConfig()
	if strictCfg.TokenExchange.Enabled == nil || !*strictCfg.TokenExchange.Enabled {
		t.Error("expected strict mode token_exchange.enabled true")
	}
	if strictCfg.TokenExchange.Path != "token" {
		t.Errorf("expected strict mode token_exchange.path 'token', got %q", strictCfg.TokenExchange.Path)
	}
	if strictCfg.WebDAVTokenExchange.Mode != "strict" {
		t.Errorf("expected strict mode webdav_token_exchange.mode 'strict', got %q", strictCfg.WebDAVTokenExchange.Mode)
	}

	// Interop mode: enabled=true, path=token, webdav_mode=lenient
	interopCfg := InteropConfig()
	if interopCfg.TokenExchange.Enabled == nil || !*interopCfg.TokenExchange.Enabled {
		t.Error("expected interop mode token_exchange.enabled true")
	}
	if interopCfg.TokenExchange.Path != "token" {
		t.Errorf("expected interop mode token_exchange.path 'token', got %q", interopCfg.TokenExchange.Path)
	}
	if interopCfg.WebDAVTokenExchange.Mode != "lenient" {
		t.Errorf("expected interop mode webdav_token_exchange.mode 'lenient', got %q", interopCfg.WebDAVTokenExchange.Mode)
	}

	// Dev mode: enabled=true, path=token, webdav_mode=lenient
	devCfg := DevConfig()
	if devCfg.TokenExchange.Enabled == nil || !*devCfg.TokenExchange.Enabled {
		t.Error("expected dev mode token_exchange.enabled true")
	}
	if devCfg.TokenExchange.Path != "token" {
		t.Errorf("expected dev mode token_exchange.path 'token', got %q", devCfg.TokenExchange.Path)
	}
	if devCfg.WebDAVTokenExchange.Mode != "lenient" {
		t.Errorf("expected dev mode webdav_token_exchange.mode 'lenient', got %q", devCfg.WebDAVTokenExchange.Mode)
	}
}

func TestLoad_TokenExchangeConfig_FromTOML(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
mode = "strict"

[token_exchange]
enabled = false
path = "token/v2"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.TokenExchange.Enabled == nil || *cfg.TokenExchange.Enabled {
		t.Error("expected token_exchange.enabled false from TOML")
	}
	if cfg.TokenExchange.Path != "token/v2" {
		t.Errorf("expected token_exchange.path 'token/v2', got %q", cfg.TokenExchange.Path)
	}
}

func TestLoad_TokenExchangeConfig_FlagsOverrideTOML(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
mode = "strict"

[token_exchange]
enabled = false
path = "token/v2"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	enabled := "true"
	path := "exchange"
	cfg, err := Load(LoaderOptions{
		ConfigPath: configPath,
		FlagOverrides: FlagOverrides{
			TokenExchangeEnabled: &enabled,
			TokenExchangePath:    &path,
		},
	})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.TokenExchange.Enabled == nil || !*cfg.TokenExchange.Enabled {
		t.Error("expected token_exchange.enabled true from flag")
	}
	if cfg.TokenExchange.Path != "exchange" {
		t.Errorf("expected token_exchange.path 'exchange' from flag, got %q", cfg.TokenExchange.Path)
	}
}

func TestLoad_TokenExchangeConfig_InvalidPath_FailsFast(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{"leading slash", "/token"},
		{"parent traversal", "token/../secret"},
		{"scheme", "http://example.com/token"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			configPath := filepath.Join(dir, "config.toml")

			tomlContent := `
mode = "strict"

[token_exchange]
path = "` + tt.path + `"
`
			if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
				t.Fatalf("failed to write config: %v", err)
			}

			_, err := Load(LoaderOptions{ConfigPath: configPath})
			if err == nil {
				t.Fatalf("expected error for invalid token_exchange.path %q", tt.path)
			}
			if !strings.Contains(err.Error(), "token_exchange.path") {
				t.Errorf("expected error to mention token_exchange.path, got: %v", err)
			}
		})
	}
}

func TestLoad_WebDAVTokenExchangeConfig_FromTOML(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
mode = "strict"

[webdav_token_exchange]
mode = "off"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.WebDAVTokenExchange.Mode != "off" {
		t.Errorf("expected webdav_token_exchange.mode 'off', got %q", cfg.WebDAVTokenExchange.Mode)
	}
}

func TestLoad_WebDAVTokenExchangeConfig_FlagsOverrideTOML(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
mode = "strict"

[webdav_token_exchange]
mode = "strict"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	mode := "lenient"
	cfg, err := Load(LoaderOptions{
		ConfigPath: configPath,
		FlagOverrides: FlagOverrides{
			WebDAVTokenExchangeMode: &mode,
		},
	})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.WebDAVTokenExchange.Mode != "lenient" {
		t.Errorf("expected webdav_token_exchange.mode 'lenient' from flag, got %q", cfg.WebDAVTokenExchange.Mode)
	}
}

func TestLoad_WebDAVTokenExchangeConfig_InvalidMode_FailsFast(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
mode = "strict"

[webdav_token_exchange]
mode = "relaxed"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error for invalid webdav_token_exchange.mode")
	}
	if !strings.Contains(err.Error(), "invalid webdav_token_exchange.mode") {
		t.Errorf("expected webdav_token_exchange.mode error, got: %v", err)
	}
}

func TestLoad_WebDAVTokenExchangeConfig_AllValidModes(t *testing.T) {
	validModes := []string{"off", "lenient", "strict"}

	for _, mode := range validModes {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			configPath := filepath.Join(dir, "config.toml")

			tomlContent := `
mode = "strict"

[webdav_token_exchange]
mode = "` + mode + `"
`
			if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
				t.Fatalf("failed to write config: %v", err)
			}

			cfg, err := Load(LoaderOptions{ConfigPath: configPath})
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}

			if cfg.WebDAVTokenExchange.Mode != mode {
				t.Errorf("expected webdav_token_exchange.mode %q, got %q", mode, cfg.WebDAVTokenExchange.Mode)
			}
		})
	}
}

func TestLoad_TokenExchangeConfig_DefaultEnabledWhenSectionMissing(t *testing.T) {
	// When [token_exchange] section is missing, enabled should default to true from preset
	cfg, err := Load(LoaderOptions{})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.TokenExchange.Enabled == nil || !*cfg.TokenExchange.Enabled {
		t.Error("expected token_exchange.enabled true by default")
	}
	if cfg.TokenExchange.Path != "token" {
		t.Errorf("expected token_exchange.path 'token' by default, got %q", cfg.TokenExchange.Path)
	}
}

func TestLoad_HTTPServices_FromTOML(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
mode = "strict"

[http.services.wellknown]
[http.services.wellknown.ocmprovider]
provider = "CustomProvider"
endpoint = "https://custom.example.com"

[http.services.ocm]
[http.services.ocm.token_exchange]
enabled = true
path = "auth/token"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if len(cfg.HTTP.Services) != 2 {
		t.Errorf("expected 2 services, got %d", len(cfg.HTTP.Services))
	}

	wellknown, ok := cfg.HTTP.Services["wellknown"]
	if !ok {
		t.Fatal("expected wellknown service in config")
	}

	ocmProvider, ok := wellknown["ocmprovider"].(map[string]any)
	if !ok {
		t.Fatal("expected ocmprovider in wellknown config")
	}
	if ocmProvider["provider"] != "CustomProvider" {
		t.Errorf("expected provider 'CustomProvider', got %v", ocmProvider["provider"])
	}

	ocm, ok := cfg.HTTP.Services["ocm"]
	if !ok {
		t.Fatal("expected ocm service in config")
	}

	tokenExchange, ok := ocm["token_exchange"].(map[string]any)
	if !ok {
		t.Fatal("expected token_exchange in ocm config")
	}
	if tokenExchange["path"] != "auth/token" {
		t.Errorf("expected path 'auth/token', got %v", tokenExchange["path"])
	}
}

func TestBuildServiceConfig_ReturnsNilForUnconfiguredService(t *testing.T) {
	cfg := StrictConfig()

	result := cfg.BuildServiceConfig("nonexistent")
	if result != nil {
		t.Errorf("expected nil for unconfigured service, got %v", result)
	}
}

func TestBuildServiceConfig_ReturnsCopyForConfiguredService(t *testing.T) {
	cfg := StrictConfig()
	cfg.HTTP.Services = map[string]map[string]any{
		"testservice": {
			"key1": "value1",
			"key2": 42,
		},
	}

	result := cfg.BuildServiceConfig("testservice")
	if result == nil {
		t.Fatal("expected non-nil result for configured service")
	}

	if result["key1"] != "value1" {
		t.Errorf("expected key1='value1', got %v", result["key1"])
	}
	if result["key2"] != 42 {
		t.Errorf("expected key2=42, got %v", result["key2"])
	}

	// Verify it's a copy (mutation doesn't affect original)
	result["key1"] = "modified"
	if cfg.HTTP.Services["testservice"]["key1"] != "value1" {
		t.Error("BuildServiceConfig should return a copy, not the original map")
	}
}

func TestBuildWellknownServiceConfig_InjectsGlobalValues(t *testing.T) {
	cfg := StrictConfig()
	cfg.PublicOrigin = "https://ocm.example.com"
	cfg.ExternalBasePath = "/api"
	cfg.Signature.AdvertiseHTTPRequestSignatures = true
	enabled := true
	cfg.TokenExchange.Enabled = &enabled
	cfg.TokenExchange.Path = "custom-token"

	result := cfg.BuildWellknownServiceConfig()
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	ocmProvider, ok := result["ocmprovider"].(map[string]any)
	if !ok {
		t.Fatal("expected ocmprovider in result")
	}

	// Check injected values
	if ocmProvider["endpoint"] != "https://ocm.example.com/api" {
		t.Errorf("expected endpoint 'https://ocm.example.com/api', got %v", ocmProvider["endpoint"])
	}
	if ocmProvider["ocm_prefix"] != "ocm" {
		t.Errorf("expected ocm_prefix 'ocm', got %v", ocmProvider["ocm_prefix"])
	}
	if ocmProvider["provider"] != "OpenCloudMesh" {
		t.Errorf("expected provider 'OpenCloudMesh', got %v", ocmProvider["provider"])
	}
	if ocmProvider["webdav_root"] != "/api/webdav/ocm/" {
		t.Errorf("expected webdav_root '/api/webdav/ocm/', got %v", ocmProvider["webdav_root"])
	}
	if ocmProvider["advertise_http_request_signatures"] != true {
		t.Errorf("expected advertise_http_request_signatures true, got %v", ocmProvider["advertise_http_request_signatures"])
	}

	tokenExchange, ok := ocmProvider["token_exchange"].(map[string]any)
	if !ok {
		t.Fatal("expected token_exchange in ocmprovider")
	}
	if tokenExchange["enabled"] != true {
		t.Errorf("expected token_exchange.enabled true, got %v", tokenExchange["enabled"])
	}
	if tokenExchange["path"] != "custom-token" {
		t.Errorf("expected token_exchange.path 'custom-token', got %v", tokenExchange["path"])
	}
}

func TestBuildWellknownServiceConfig_ExplicitConfigOverridesDefaults(t *testing.T) {
	cfg := StrictConfig()
	cfg.PublicOrigin = "https://ocm.example.com"
	cfg.HTTP.Services = map[string]map[string]any{
		"wellknown": {
			"ocmprovider": map[string]any{
				"provider": "CustomProvider",
				"endpoint": "https://custom.example.com",
			},
		},
	}

	result := cfg.BuildWellknownServiceConfig()
	ocmProvider, ok := result["ocmprovider"].(map[string]any)
	if !ok {
		t.Fatal("expected ocmprovider in result")
	}

	// Explicit values should override defaults
	if ocmProvider["provider"] != "CustomProvider" {
		t.Errorf("expected provider 'CustomProvider', got %v", ocmProvider["provider"])
	}
	if ocmProvider["endpoint"] != "https://custom.example.com" {
		t.Errorf("expected endpoint 'https://custom.example.com', got %v", ocmProvider["endpoint"])
	}
}

func TestBuildOCMServiceConfig_InjectsTokenExchangeSettings(t *testing.T) {
	cfg := StrictConfig()
	enabled := true
	cfg.TokenExchange.Enabled = &enabled
	cfg.TokenExchange.Path = "auth/token"

	result := cfg.BuildOCMServiceConfig()
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	tokenExchange, ok := result["token_exchange"].(map[string]any)
	if !ok {
		t.Fatal("expected token_exchange in result")
	}

	if tokenExchange["enabled"] != true {
		t.Errorf("expected enabled true, got %v", tokenExchange["enabled"])
	}
	if tokenExchange["path"] != "auth/token" {
		t.Errorf("expected path 'auth/token', got %v", tokenExchange["path"])
	}
}

func TestBuildOCMServiceConfig_ExplicitConfigOverridesDefaults(t *testing.T) {
	cfg := StrictConfig()
	enabled := true
	cfg.TokenExchange.Enabled = &enabled
	cfg.TokenExchange.Path = "default-token"
	cfg.HTTP.Services = map[string]map[string]any{
		"ocm": {
			"token_exchange": map[string]any{
				"enabled": false,
				"path":    "custom-path",
			},
		},
	}

	result := cfg.BuildOCMServiceConfig()
	tokenExchange, ok := result["token_exchange"].(map[string]any)
	if !ok {
		t.Fatal("expected token_exchange in result")
	}

	// Explicit values should override defaults
	if tokenExchange["enabled"] != false {
		t.Errorf("expected enabled false from explicit config, got %v", tokenExchange["enabled"])
	}
	if tokenExchange["path"] != "custom-path" {
		t.Errorf("expected path 'custom-path' from explicit config, got %v", tokenExchange["path"])
	}
}

func TestBuildWellknownServiceConfig_NoBasePath(t *testing.T) {
	cfg := StrictConfig()
	cfg.PublicOrigin = "https://ocm.example.com"
	cfg.ExternalBasePath = "" // no base path

	result := cfg.BuildWellknownServiceConfig()
	ocmProvider, ok := result["ocmprovider"].(map[string]any)
	if !ok {
		t.Fatal("expected ocmprovider in result")
	}

	if ocmProvider["endpoint"] != "https://ocm.example.com" {
		t.Errorf("expected endpoint 'https://ocm.example.com', got %v", ocmProvider["endpoint"])
	}
	if ocmProvider["webdav_root"] != "/webdav/ocm/" {
		t.Errorf("expected webdav_root '/webdav/ocm/', got %v", ocmProvider["webdav_root"])
	}
}

func TestHTTPConfig_EmptyServicesDoesNotBreakLoading(t *testing.T) {
	cfg, err := Load(LoaderOptions{})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// HTTP.Services should be nil or empty by default
	if cfg.HTTP.Services != nil && len(cfg.HTTP.Services) > 0 {
		t.Errorf("expected empty HTTP.Services by default, got %d services", len(cfg.HTTP.Services))
	}
}

func TestBuildWellknownServiceConfig_APIVersionOverrides_InteropMode(t *testing.T) {
	cfg := InteropConfig()
	cfg.PublicOrigin = "https://ocm.example.com"

	result := cfg.BuildWellknownServiceConfig()
	ocmProvider, ok := result["ocmprovider"].(map[string]any)
	if !ok {
		t.Fatal("expected ocmprovider in result")
	}

	// In interop mode, should inject Nextcloud crawler override
	overrides, ok := ocmProvider["api_version_overrides"].([]map[string]any)
	if !ok {
		t.Fatal("expected api_version_overrides in ocmprovider for interop mode")
	}
	if len(overrides) != 1 {
		t.Fatalf("expected 1 override, got %d", len(overrides))
	}
	if overrides[0]["user_agent_contains"] != "Nextcloud Server Crawler" {
		t.Errorf("expected user_agent_contains 'Nextcloud Server Crawler', got %v", overrides[0]["user_agent_contains"])
	}
	if overrides[0]["api_version"] != "1.1" {
		t.Errorf("expected api_version '1.1', got %v", overrides[0]["api_version"])
	}
}

func TestBuildWellknownServiceConfig_APIVersionOverrides_DevMode(t *testing.T) {
	cfg := DevConfig()
	cfg.PublicOrigin = "https://ocm.example.com"

	result := cfg.BuildWellknownServiceConfig()
	ocmProvider, ok := result["ocmprovider"].(map[string]any)
	if !ok {
		t.Fatal("expected ocmprovider in result")
	}

	// In dev mode, should also inject Nextcloud crawler override
	overrides, ok := ocmProvider["api_version_overrides"].([]map[string]any)
	if !ok {
		t.Fatal("expected api_version_overrides in ocmprovider for dev mode")
	}
	if len(overrides) != 1 {
		t.Fatalf("expected 1 override, got %d", len(overrides))
	}
}

func TestBuildWellknownServiceConfig_APIVersionOverrides_StrictMode(t *testing.T) {
	cfg := StrictConfig()
	cfg.PublicOrigin = "https://ocm.example.com"

	result := cfg.BuildWellknownServiceConfig()
	ocmProvider, ok := result["ocmprovider"].(map[string]any)
	if !ok {
		t.Fatal("expected ocmprovider in result")
	}

	// In strict mode, should NOT inject overrides
	if _, ok := ocmProvider["api_version_overrides"]; ok {
		t.Error("expected no api_version_overrides in strict mode")
	}
}

func TestValidatePublicOrigin_ValidValues(t *testing.T) {
	valid := []struct {
		name   string
		origin string
	}{
		{"https basic", "https://example.com"},
		{"https with trailing slash", "https://example.com/"},
		{"https with port", "https://example.com:8443"},
		{"https with port and trailing slash", "https://example.com:8443/"},
		{"http basic", "http://example.com"},
		{"http with port", "http://example.com:8080"},
		{"https default port explicit", "https://example.com:443"},
		{"http default port explicit", "http://example.com:80"},
		{"localhost", "https://localhost"},
		{"localhost with port", "https://localhost:9200"},
		{"ipv4", "https://192.168.1.1"},
		{"ipv4 with port", "https://192.168.1.1:9200"},
		{"ipv6 bracketed", "https://[::1]"},
		{"ipv6 bracketed with port", "https://[::1]:9200"},
		{"empty skips validation", ""},
	}

	for _, tt := range valid {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{PublicOrigin: tt.origin}
			if err := validatePublicOrigin(cfg); err != nil {
				t.Errorf("validatePublicOrigin(%q) unexpected error: %v", tt.origin, err)
			}
		})
	}
}

func TestValidatePublicOrigin_InvalidValues(t *testing.T) {
	tests := []struct {
		name      string
		origin    string
		wantInErr string
	}{
		{
			"no scheme",
			"example.com",
			"must be an absolute URL",
		},
		{
			"ftp scheme",
			"ftp://example.com",
			"scheme must be http or https",
		},
		{
			"has userinfo",
			"https://user:pass@example.com",
			"must not include userinfo",
		},
		{
			"has query",
			"https://example.com?foo=bar",
			"must not include a query string",
		},
		{
			"has fragment",
			"https://example.com#section",
			"must not include a fragment",
		},
		{
			"has base path",
			"https://example.com/app",
			"must not include a path",
		},
		{
			"has deeper path",
			"https://example.com/api/v1",
			"must not include a path",
		},
		{
			"leading whitespace",
			" https://example.com",
			"must not contain leading or trailing whitespace",
		},
		{
			"trailing whitespace",
			"https://example.com ",
			"must not contain leading or trailing whitespace",
		},
		{
			"leading tab",
			"\thttps://example.com",
			"must not contain leading or trailing whitespace",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{PublicOrigin: tt.origin}
			err := validatePublicOrigin(cfg)
			if err == nil {
				t.Fatalf("validatePublicOrigin(%q) expected error, got nil", tt.origin)
			}
			if !strings.Contains(err.Error(), tt.wantInErr) {
				t.Errorf("validatePublicOrigin(%q) error = %q, want substring %q", tt.origin, err.Error(), tt.wantInErr)
			}
		})
	}
}

func TestLoad_PublicOrigin_InvalidViaConfigFile_FailsFast(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
mode = "dev"
public_origin = "https://example.com/app"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error for public_origin with a path")
	}
	if !strings.Contains(err.Error(), "public_origin") {
		t.Errorf("expected error to mention public_origin, got: %v", err)
	}
}

func TestLoad_ExternalOrigin_StrictBreak_FailsFast(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
mode = "dev"
external_origin = "https://example.com"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error for old external_origin key")
	}
	if !strings.Contains(err.Error(), "external_origin") || !strings.Contains(err.Error(), "public_origin") {
		t.Errorf("expected error to mention both external_origin and public_origin, got: %v", err)
	}
}

func TestLoad_PublicOrigin_InvalidViaFlag_FailsFast(t *testing.T) {
	origin := "ftp://example.com"
	_, err := Load(LoaderOptions{
		FlagOverrides: FlagOverrides{
			PublicOrigin: &origin,
		},
	})
	if err == nil {
		t.Fatal("expected error for ftp scheme in public_origin")
	}
	if !strings.Contains(err.Error(), "scheme must be http or https") {
		t.Errorf("expected scheme error, got: %v", err)
	}
}

func TestLoad_PublicOrigin_ValidViaConfigFile_Succeeds(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
mode = "dev"
public_origin = "https://example.com:9200"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.PublicOrigin != "https://example.com:9200" {
		t.Errorf("expected public_origin https://example.com:9200, got %s", cfg.PublicOrigin)
	}
}

func TestLoad_PeerProfileCustomFields(t *testing.T) {
	// Verify that RelaxMustExchangeToken and AllowedBasicAuthPatterns
	// round-trip through TOML deserialization into config.PeerProfile.
	// This catches the silent zero-value regression that existed before
	// these fields were added to config.PeerProfile.
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
public_origin = "https://localhost:9200"
mode = "interop"

[peer_profiles.custom_profiles.test_peer]
allow_unsigned_inbound = true
allow_unsigned_outbound = false
allow_mismatched_host = true
allow_http = false
token_exchange_quirks = ["accept_plain_token"]
relax_must_exchange_token = true
allowed_basic_auth_patterns = ["token:", "id:token"]
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	profile, ok := cfg.PeerProfiles.CustomProfiles["test_peer"]
	if !ok {
		t.Fatal("expected custom profile 'test_peer' to exist")
	}
	if !profile.AllowUnsignedInbound {
		t.Error("expected AllowUnsignedInbound = true")
	}
	if profile.AllowUnsignedOutbound {
		t.Error("expected AllowUnsignedOutbound = false")
	}
	if !profile.AllowMismatchedHost {
		t.Error("expected AllowMismatchedHost = true")
	}
	if !profile.RelaxMustExchangeToken {
		t.Error("expected RelaxMustExchangeToken = true, got false (field not deserialized from TOML)")
	}
	if len(profile.AllowedBasicAuthPatterns) != 2 {
		t.Errorf("expected 2 AllowedBasicAuthPatterns, got %d (field not deserialized from TOML)", len(profile.AllowedBasicAuthPatterns))
	} else {
		if profile.AllowedBasicAuthPatterns[0] != "token:" {
			t.Errorf("expected first pattern 'token:', got %q", profile.AllowedBasicAuthPatterns[0])
		}
		if profile.AllowedBasicAuthPatterns[1] != "id:token" {
			t.Errorf("expected second pattern 'id:token', got %q", profile.AllowedBasicAuthPatterns[1])
		}
	}
}
