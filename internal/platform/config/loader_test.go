package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/ocmtest/configfixture"
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
mode = "interop"
[signature]
advertise_http_request_signatures = true
`,
		},
		{
			name: "dotted root key",
			config: `
mode = "interop"
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
mode = "interop"

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

[peer_trust.policy]
global_enforce = true
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

func TestLoad_FederationTOMLUnsupported_Fails(t *testing.T) {
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
		t.Fatal("expected error for unsupported [federation] TOML section")
	}
	if !strings.Contains(err.Error(), "federation") {
		t.Errorf("expected error mentioning federation, got: %v", err)
	}
}

func TestLoad_FederationDottedKeyUnsupported_Fails(t *testing.T) {
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
		t.Fatal("expected error for unsupported federation.enabled dotted key")
	}
	if !strings.Contains(err.Error(), "federation") {
		t.Errorf("expected error mentioning federation, got: %v", err)
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

func TestLoad_PeerProfileCustomFields(t *testing.T) {
	// Verify custom profile fields still round-trip into config.PeerProfile.
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
allow_unsigned_discovery = true
token_exchange_quirks = ["accept_plain_token"]
token_exchange_grant_type = "ocm_share"
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
	if !profile.AllowUnsignedDiscovery {
		t.Error("expected AllowUnsignedDiscovery = true")
	}
	if profile.TokenExchangeGrantType != "ocm_share" {
		t.Errorf("expected TokenExchangeGrantType %q, got %q", "ocm_share", profile.TokenExchangeGrantType)
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

func TestLoad_PeerPolicy_ValidValues(t *testing.T) {
	validPolicies := []string{"legacy", "prefer-strict", "strict"}

	for _, policy := range validPolicies {
		t.Run(policy, func(t *testing.T) {
			dir := t.TempDir()
			configPath := filepath.Join(dir, "config.toml")

			tomlContent := `
mode = "compat"
peer_policy = "` + policy + `"

[token_exchange]
enabled = true
`
			if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
				t.Fatalf("failed to write config: %v", err)
			}

			cfg, err := Load(LoaderOptions{ConfigPath: configPath})
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}

			if cfg.PeerPolicy != policy {
				t.Errorf("expected peer_policy %q, got %q", policy, cfg.PeerPolicy)
			}
		})
	}
}

func TestLoad_PeerPolicy_InvalidFails(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
mode = "strict"
peer_policy = "unknown"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error for invalid peer_policy")
	}
	if !strings.Contains(err.Error(), "peer_policy") {
		t.Errorf("expected error about peer_policy, got: %v", err)
	}
}

func TestLoad_NonStrictPeerOutboundPolicy_UnsupportedFails(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
mode = "strict"
non_strict_peer_outbound_policy = "prefer-strict"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error for unsupported non_strict_peer_outbound_policy key")
	}
	if !strings.Contains(err.Error(), "non_strict_peer_outbound_policy") {
		t.Errorf("expected error mentioning non_strict_peer_outbound_policy, got: %v", err)
	}
}

func TestLoad_LegacyPeerPolicy_UnsupportedFails(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
mode = "strict"
legacy_peer_policy = "prefer-strict"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error for unsupported legacy_peer_policy key")
	}
	if !strings.Contains(err.Error(), "legacy_peer_policy") {
		t.Errorf("expected error mentioning legacy_peer_policy, got: %v", err)
	}
}

func TestLoad_CrossField_RequireTokenExchangeRequiresTokenExchange(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
mode = "strict"
require_token_exchange = true

[token_exchange]
enabled = false
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error for require_token_exchange without token exchange capability")
	}
	if !strings.Contains(err.Error(), "require_token_exchange=true requires token_exchange.enabled=true") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestLoad_CrossField_StrictPeerPolicyRequiresTokenExchange(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
mode = "strict"
require_token_exchange = false
peer_policy = "strict"

[token_exchange]
enabled = false
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error for strict peer policy without token exchange")
	}
	if !strings.Contains(err.Error(), "peer_policy=strict requires token_exchange.enabled=true") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestLoad_StrictModeSignatureContradictions_FailFast(t *testing.T) {
	tests := []struct {
		name      string
		signature string
		wantError string
	}{
		{
			name: "strict mode requires inbound strict",
			signature: `
[signature]
inbound_mode = "lenient"
`,
			wantError: "compatibility_scope=none requires signature.inbound_mode=strict",
		},
		{
			name: "strict mode requires outbound strict",
			signature: `
[signature]
outbound_mode = "criteria-only"
`,
			wantError: "compatibility_scope=none requires signature.outbound_mode=strict",
		},
		{
			name: "strict mode requires peer override off",
			signature: `
[signature]
peer_profile_level_override = "non-strict"
`,
			wantError: "compatibility_scope=none requires signature.peer_profile_level_override=off",
		},
		{
			name: "strict mode requires discovery errors rejected",
			signature: `
[signature]
on_discovery_error = "allow"
`,
			wantError: "compatibility_scope=none requires signature.on_discovery_error=reject",
		},
		{
			name: "strict mode disallows mismatch",
			signature: `
[signature]
allow_mismatch = true
`,
			wantError: "compatibility_scope=none requires signature.allow_mismatch=false",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			configPath := filepath.Join(dir, "config.toml")
			tomlContent := `
mode = "strict"
` + tt.signature
			if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
				t.Fatalf("failed to write config: %v", err)
			}

			_, err := Load(LoaderOptions{ConfigPath: configPath})
			if err == nil {
				t.Fatalf("expected strict-mode contradiction error: %s", tt.wantError)
			}
			if !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("expected %q, got %v", tt.wantError, err)
			}
		})
	}
}

func TestLoad_StrictMode_WithHardenedDefaults_Succeeds(t *testing.T) {
	cfg, err := Load(LoaderOptions{ModeFlag: "strict"})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Signature.InboundMode != "strict" {
		t.Errorf("expected inbound strict, got %q", cfg.Signature.InboundMode)
	}
	if cfg.Signature.OutboundMode != "strict" {
		t.Errorf("expected outbound strict, got %q", cfg.Signature.OutboundMode)
	}
	if cfg.Signature.PeerProfileLevelOverride != "off" {
		t.Errorf("expected peer_profile_level_override off, got %q", cfg.Signature.PeerProfileLevelOverride)
	}
	if cfg.Signature.OnDiscoveryError != "reject" {
		t.Errorf("expected on_discovery_error reject, got %q", cfg.Signature.OnDiscoveryError)
	}
	if cfg.Signature.AllowMismatch {
		t.Error("expected allow_mismatch false")
	}
}

func TestLoad_CrossField_PeerOverrideAllIncompatibleWithStrict(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
mode = "strict"

[signature]
peer_profile_level_override = "all"

[token_exchange]
enabled = true
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error for peer_profile_level_override=all with strict mode")
	}
	if !strings.Contains(err.Error(), "compatibility_scope=none requires signature.peer_profile_level_override=off") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestLoad_NoneScope_PeerProfileMappingsRejected(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	tomlContent := `mode = "strict"

[[peer_profiles.mappings]]
pattern = "peer.example.com"
profile = "some-compat"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error for peer_profiles.mappings under compatibility_scope=none")
	}
	if !strings.Contains(err.Error(), "compatibility_scope=none forbids peer_profiles.mappings") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestLoad_NoneScope_CustomProfiles_RelaxingFields_Rejected(t *testing.T) {
	tests := []struct {
		name      string
		extra     string
		wantError string
	}{
		{
			name: "rejects allow_unsigned_inbound",
			extra: `
[peer_profiles.custom_profiles.peer-a]
allow_unsigned_inbound = true
`,
			wantError: "compatibility_scope=none forbids peer_profiles.custom_profiles.peer-a.allow_unsigned_inbound",
		},
		{
			name: "rejects allow_unsigned_outbound",
			extra: `
[peer_profiles.custom_profiles.peer-a]
allow_unsigned_outbound = true
`,
			wantError: "compatibility_scope=none forbids peer_profiles.custom_profiles.peer-a.allow_unsigned_outbound",
		},
		{
			name: "rejects allow_mismatched_host",
			extra: `
[peer_profiles.custom_profiles.peer-a]
allow_mismatched_host = true
`,
			wantError: "compatibility_scope=none forbids peer_profiles.custom_profiles.peer-a.allow_mismatched_host",
		},
		{
			name: "rejects allow_http",
			extra: `
[peer_profiles.custom_profiles.peer-a]
allow_http = true
`,
			wantError: "compatibility_scope=none forbids peer_profiles.custom_profiles.peer-a.allow_http",
		},
		{
			name: "rejects allow_unsigned_discovery",
			extra: `
[peer_profiles.custom_profiles.peer-a]
allow_unsigned_discovery = true
`,
			wantError: "compatibility_scope=none forbids peer_profiles.custom_profiles.peer-a.allow_unsigned_discovery",
		},
		{
			name: "rejects accept_legacy_discovery_public_key",
			extra: `
[peer_profiles.custom_profiles.peer-a]
accept_legacy_discovery_public_key = true
`,
			wantError: "compatibility_scope=none forbids peer_profiles.custom_profiles.peer-a.accept_legacy_discovery_public_key",
		},
		{
			name: "rejects token_exchange_grant_type",
			extra: `
[peer_profiles.custom_profiles.peer-a]
token_exchange_grant_type = "ocm_share"
`,
			wantError: "compatibility_scope=none forbids peer_profiles.custom_profiles.peer-a.token_exchange_grant_type",
		},
		{
			name: "rejects token_exchange_quirks",
			extra: `
[peer_profiles.custom_profiles.peer-a]
token_exchange_quirks = ["accept_plain_token"]
`,
			wantError: "compatibility_scope=none forbids peer_profiles.custom_profiles.peer-a.token_exchange_quirks",
		},
		{
			name: "rejects allowed_basic_auth_patterns",
			extra: `
[peer_profiles.custom_profiles.peer-a]
allowed_basic_auth_patterns = ["token:"]
`,
			wantError: "compatibility_scope=none forbids peer_profiles.custom_profiles.peer-a.allowed_basic_auth_patterns",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			configPath := filepath.Join(dir, "config.toml")
			tomlContent := `mode = "strict"
` + tt.extra
			if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
				t.Fatalf("failed to write config: %v", err)
			}

			_, err := Load(LoaderOptions{ConfigPath: configPath})
			if err == nil {
				t.Fatalf("expected none-scope custom profile rejection: %s", tt.wantError)
			}
			if !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("expected %q, got %v", tt.wantError, err)
			}
		})
	}
}

func TestLoad_NoneScope_RequireTokenExchangeFalse_FailFast(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	tomlContent := `mode = "strict"
require_token_exchange = false
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error for require_token_exchange=false under compatibility_scope=none")
	}
	if !strings.Contains(err.Error(), "compatibility_scope=none requires require_token_exchange=true") {
		t.Fatalf("expected none-scope require_token_exchange error, got: %v", err)
	}
}

func TestLoad_ScopedCompatibilityRejectsGlobalRelaxations(t *testing.T) {
	tests := []struct {
		name      string
		extra     string
		wantError string
	}{
		{
			name: "rejects inbound lenient",
			extra: `
[signature]
inbound_mode = "lenient"
`,
			wantError: "compatibility_scope=scoped requires signature.inbound_mode=strict",
		},
		{
			name: "rejects outbound token only",
			extra: `
[signature]
outbound_mode = "token-only"
`,
			wantError: "compatibility_scope=scoped requires signature.outbound_mode=strict",
		},
		{
			name: "rejects peer override all",
			extra: `
[signature]
peer_profile_level_override = "all"
`,
			wantError: "compatibility_scope=scoped requires signature.peer_profile_level_override!=all",
		},
		{
			name: "rejects discovery fail open",
			extra: `
[signature]
on_discovery_error = "allow"
`,
			wantError: "compatibility_scope=scoped requires signature.on_discovery_error=reject",
		},
		{
			name: "rejects mismatch allowance",
			extra: `
[signature]
allow_mismatch = true
`,
			wantError: "compatibility_scope=scoped requires signature.allow_mismatch=false",
		},
		{
			name: "rejects tls off",
			extra: `
[tls]
mode = "off"
`,
			wantError: "compatibility_scope=scoped requires tls.mode!=off",
		},
		{
			name: "rejects ssrf off",
			extra: `
[outbound_http.ssrf]
mode = "off"
`,
			wantError: "compatibility_scope=scoped requires outbound_http.ssrf.mode=strict",
		},
		{
			name: "rejects insecure skip verify",
			extra: `
[outbound_http]
insecure_skip_verify = true
`,
			wantError: "compatibility_scope=scoped requires outbound_http.insecure_skip_verify=false",
		},
		{
			name: "rejects fail open peer trust",
			extra: `
[peer_trust]
enabled = true
config_paths = ["trust-group.json"]

[peer_trust.policy]
global_enforce = false
`,
			wantError: "compatibility_scope=scoped requires peer_trust.policy.global_enforce=true when peer trust is enabled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			configPath := filepath.Join(dir, "config.toml")
			tomlContent := configfixture.ScopedScopeBase() + tt.extra
			if strings.Contains(tt.extra, "[peer_trust]") {
				trustGroupPath := filepath.Join(dir, "trust-group.json")
				if err := os.WriteFile(trustGroupPath, []byte(`{}`), 0644); err != nil {
					t.Fatalf("failed to write trust group fixture: %v", err)
				}
				tomlContent = strings.ReplaceAll(tomlContent, "trust-group.json", trustGroupPath)
			}
			if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
				t.Fatalf("failed to write config: %v", err)
			}

			_, err := Load(LoaderOptions{ConfigPath: configPath})
			if err == nil {
				t.Fatalf("expected scoped compatibility error: %s", tt.wantError)
			}
			if !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("expected %q, got %v", tt.wantError, err)
			}
		})
	}
}

func TestLoad_ScopedCompatibilityAllowsPeerScopedRelaxationWiring(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
mode = "strict"
compatibility_scope = "scoped"

[signature]
peer_profile_level_override = "non-strict"

[[peer_profiles.mappings]]
pattern = "peer.example.com"
profile = "compat"

[peer_profiles.custom_profiles.compat]
allow_mismatched_host = true
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() unexpected error = %v", err)
	}

	if cfg.CompatibilityScope != "scoped" {
		t.Fatalf("expected compatibility_scope scoped, got %q", cfg.CompatibilityScope)
	}
	if cfg.Signature.PeerProfileLevelOverride != "non-strict" {
		t.Fatalf("expected peer_profile_level_override non-strict, got %q", cfg.Signature.PeerProfileLevelOverride)
	}
}

func TestLoad_PeerPolicy_DefaultIsStrict(t *testing.T) {
	cfg, err := Load(LoaderOptions{})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.PeerPolicy != "strict" {
		t.Errorf("expected default peer_policy strict, got %q", cfg.PeerPolicy)
	}
}
