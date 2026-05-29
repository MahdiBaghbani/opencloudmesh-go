package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/ocmtest/configfixture"
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
	if cfg.OutboundHTTP.SSRF.Mode != "strict" {
		t.Errorf("expected SSRF mode strict, got %s", cfg.OutboundHTTP.SSRF.Mode)
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
	if cfg.OutboundHTTP.SSRF.Mode != "off" {
		t.Errorf("expected SSRF mode off in dev, got %s", cfg.OutboundHTTP.SSRF.Mode)
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
timeout_ms = 5000

[outbound_http.ssrf]
mode = "strict"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Mode != "compat" {
		t.Errorf("expected mode compat, got %s", cfg.Mode)
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
	if cfg.OutboundHTTP.SSRF.Mode != "strict" {
		t.Errorf("expected SSRF mode strict from TOML, got %s", cfg.OutboundHTTP.SSRF.Mode)
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
mode = "interop"
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
			PublicOrigin:         &origin,
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
	if cfg.OutboundHTTP.SSRF.Mode != "off" {
		t.Errorf("expected SSRF mode off from dev preset, got %s", cfg.OutboundHTTP.SSRF.Mode)
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
	if cfg.CompatibilityScope != "none" {
		t.Errorf("expected compatibility scope none, got %s", cfg.CompatibilityScope)
	}
	if cfg.OutboundHTTP.SSRF.Mode != "strict" {
		t.Errorf("expected SSRF mode strict, got %s", cfg.OutboundHTTP.SSRF.Mode)
	}
	if cfg.Signature.InboundMode != "strict" {
		t.Errorf("expected signature inbound mode strict, got %s", cfg.Signature.InboundMode)
	}
	if cfg.Signature.OutboundMode != "strict" {
		t.Errorf("expected signature outbound mode strict, got %s", cfg.Signature.OutboundMode)
	}
	if cfg.Signature.PeerProfileLevelOverride != "off" {
		t.Errorf("expected peer_profile_level_override off, got %s", cfg.Signature.PeerProfileLevelOverride)
	}
	if cfg.OutboundHTTP.InsecureSkipVerify {
		t.Error("expected InsecureSkipVerify false in strict")
	}
	if cfg.OutboundHTTP.MaxRedirects != 1 {
		t.Errorf("expected MaxRedirects 1 in strict, got %d", cfg.OutboundHTTP.MaxRedirects)
	}
	if cfg.PeerPolicy != "strict" {
		t.Errorf("expected peer_policy strict in strict config, got %q", cfg.PeerPolicy)
	}
}

func TestDevConfig(t *testing.T) {
	cfg := DevConfig()

	if cfg.Mode != "dev" {
		t.Errorf("expected mode dev, got %s", cfg.Mode)
	}
	if cfg.CompatibilityScope != "unbounded" {
		t.Errorf("expected compatibility scope unbounded, got %s", cfg.CompatibilityScope)
	}
	if cfg.OutboundHTTP.SSRF.Mode != "off" {
		t.Errorf("expected SSRF mode off, got %s", cfg.OutboundHTTP.SSRF.Mode)
	}
	if cfg.TLS.Mode != "off" {
		t.Errorf("expected TLS mode off, got %s", cfg.TLS.Mode)
	}
	if !cfg.OutboundHTTP.InsecureSkipVerify {
		t.Error("expected InsecureSkipVerify true in dev")
	}
}

func TestCompatConfig(t *testing.T) {
	cfg := CompatConfig()

	if cfg.Mode != "compat" {
		t.Errorf("expected mode compat, got %s", cfg.Mode)
	}
	if cfg.CompatibilityScope != "unbounded" {
		t.Errorf("expected compatibility scope unbounded, got %s", cfg.CompatibilityScope)
	}
	if cfg.Signature.InboundMode != "lenient" {
		t.Errorf("expected signature inbound mode lenient, got %s", cfg.Signature.InboundMode)
	}
	if cfg.Signature.OutboundMode != "criteria-only" {
		t.Errorf("expected signature outbound mode criteria-only, got %s", cfg.Signature.OutboundMode)
	}
	// SSRF stays strict in compat
	if cfg.OutboundHTTP.SSRF.Mode != "strict" {
		t.Errorf("expected SSRF mode strict in compat, got %s", cfg.OutboundHTTP.SSRF.Mode)
	}
}

// TestDevConfig_DerivesFromStrict pins the behavior-preserving contract for
// DevConfig now that it overlays StrictConfig. It checks every dev-specific
// delta, confirms shared defaults stay inherited from strict, and guards
// against token-exchange pointer aliasing across separate preset calls.
func TestDevConfig_DerivesFromStrict(t *testing.T) {
	dev := DevConfig()
	strict := StrictConfig()

	// Dev-specific deltas relative to strict.
	deltas := []struct {
		name string
		got  any
		want any
	}{
		{"Mode", dev.Mode, "dev"},
		{"CompatibilityScope", dev.CompatibilityScope, "unbounded"},
		{"TLS.Mode", dev.TLS.Mode, "off"},
		{"TLS.ACME.Directory", dev.TLS.ACME.Directory, "https://acme-staging-v02.api.letsencrypt.org/directory"},
		{"TLS.ACME.UseStaging", dev.TLS.ACME.UseStaging, true},
		{"OutboundHTTP.SSRF.Mode", dev.OutboundHTTP.SSRF.Mode, "off"},
		{"OutboundHTTP.SSRFMode", dev.OutboundHTTP.SSRFMode, "off"},
		{"OutboundHTTP.MaxRedirects", dev.OutboundHTTP.MaxRedirects, 3},
		{"OutboundHTTP.InsecureSkipVerify", dev.OutboundHTTP.InsecureSkipVerify, true},
		{"OutboundHTTP.ProxyEnvFallback", dev.OutboundHTTP.ProxyEnvFallback, false},
		{"Signature.InboundMode", dev.Signature.InboundMode, "lenient"},
		{"Signature.OutboundMode", dev.Signature.OutboundMode, "criteria-only"},
		{"Signature.PeerProfileLevelOverride", dev.Signature.PeerProfileLevelOverride, "non-strict"},
		{"Signature.OnDiscoveryError", dev.Signature.OnDiscoveryError, "allow"},
		{"Signature.AllowMismatch", dev.Signature.AllowMismatch, true},
		{"Logging.Level", dev.Logging.Level, "debug"},
		{"RequireTokenExchange", dev.RequireTokenExchange, false},
		{"PeerPolicy", dev.PeerPolicy, "prefer-strict"},
	}
	for _, d := range deltas {
		if d.got != d.want {
			t.Errorf("dev delta %s = %v, want %v", d.name, d.got, d.want)
		}
	}

	// Shared defaults must remain inherited from strict.
	inherited := []struct {
		name string
		got  any
		want any
	}{
		{"PublicOrigin", dev.PublicOrigin, strict.PublicOrigin},
		{"ExternalBasePath", dev.ExternalBasePath, strict.ExternalBasePath},
		{"ListenAddr", dev.ListenAddr, strict.ListenAddr},
		{"TLS.HTTPPort", dev.TLS.HTTPPort, strict.TLS.HTTPPort},
		{"TLS.HTTPSPort", dev.TLS.HTTPSPort, strict.TLS.HTTPSPort},
		{"TLS.SelfSignedDir", dev.TLS.SelfSignedDir, strict.TLS.SelfSignedDir},
		{"TLS.ACME.StorageDir", dev.TLS.ACME.StorageDir, strict.TLS.ACME.StorageDir},
		{"OutboundHTTP.TimeoutMS", dev.OutboundHTTP.TimeoutMS, strict.OutboundHTTP.TimeoutMS},
		{"OutboundHTTP.ConnectTimeoutMS", dev.OutboundHTTP.ConnectTimeoutMS, strict.OutboundHTTP.ConnectTimeoutMS},
		{"OutboundHTTP.MaxResponseBytes", dev.OutboundHTTP.MaxResponseBytes, strict.OutboundHTTP.MaxResponseBytes},
		{"Signature.KeyPath", dev.Signature.KeyPath, strict.Signature.KeyPath},
		{"PeerTrust.Enabled", dev.PeerTrust.Enabled, strict.PeerTrust.Enabled},
		{"PeerTrust.MembershipCache.TTLSeconds", dev.PeerTrust.MembershipCache.TTLSeconds, strict.PeerTrust.MembershipCache.TTLSeconds},
		{"PeerTrust.MembershipCache.MaxStaleSeconds", dev.PeerTrust.MembershipCache.MaxStaleSeconds, strict.PeerTrust.MembershipCache.MaxStaleSeconds},
		{"Logging.AllowSensitive", dev.Logging.AllowSensitive, strict.Logging.AllowSensitive},
		{"TokenExchange.Path", dev.TokenExchange.Path, strict.TokenExchange.Path},
	}
	for _, i := range inherited {
		if i.got != i.want {
			t.Errorf("dev inherited %s = %v, want strict value %v", i.name, i.got, i.want)
		}
	}

	if got := strings.Join(dev.Server.TrustedProxies, ","); got != strings.Join(strict.Server.TrustedProxies, ",") {
		t.Errorf("dev TrustedProxies = %v, want strict value %v", dev.Server.TrustedProxies, strict.Server.TrustedProxies)
	}

	// Token-exchange enabled pointer value is preserved (true).
	if dev.TokenExchange.Enabled == nil || !*dev.TokenExchange.Enabled {
		t.Fatal("expected dev token_exchange.enabled pointer to be non-nil true")
	}

	// Guard against pointer aliasing: separate preset calls must own distinct
	// pointers so mutating one config never leaks into another.
	if dev.TokenExchange.Enabled == strict.TokenExchange.Enabled {
		t.Error("dev and strict share the same token_exchange.enabled pointer")
	}
	dev2 := DevConfig()
	if dev.TokenExchange.Enabled == dev2.TokenExchange.Enabled {
		t.Error("two DevConfig calls share the same token_exchange.enabled pointer")
	}
	*dev.TokenExchange.Enabled = false
	if dev2.TokenExchange.Enabled == nil || !*dev2.TokenExchange.Enabled {
		t.Error("mutating one DevConfig token_exchange.enabled affected another")
	}
}

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

func TestLoad_OldFlatSSRFKey_Fails(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
[outbound_http]
ssrf_mode = "strict"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error for unsupported outbound_http.ssrf_mode key")
	}
	if !strings.Contains(err.Error(), "outbound_http.ssrf_mode") {
		t.Errorf("expected error mentioning outbound_http.ssrf_mode, got: %v", err)
	}
}

func TestLoad_InvalidNestedSSRFMode_FailsFast(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
[outbound_http.ssrf]
mode = "block"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error for invalid outbound_http.ssrf.mode")
	}
	if !strings.Contains(err.Error(), "invalid outbound_http.ssrf.mode") {
		t.Errorf("expected ssrf.mode error, got: %v", err)
	}
}

func TestLoad_SSRF_NestedSchemaLoads(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
mode = "interop"

[outbound_http.ssrf]
mode = "strict"

[outbound_http.ssrf.route_policies.internal]
allow_private_host_suffixes = ["svc.cluster.local"]
allow_private_cidrs = ["10.0.0.0/8"]
allowed_ports = [8080, 8443]
allow_ip_literals = false
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v (nested SSRF schema should load)", err)
	}

	if cfg.OutboundHTTP.SSRF.Mode != "strict" {
		t.Errorf("expected ssrf.mode strict, got %q", cfg.OutboundHTTP.SSRF.Mode)
	}
	policy, ok := cfg.OutboundHTTP.SSRF.RoutePolicies["internal"]
	if !ok {
		t.Fatal("expected route policy 'internal' to be defined")
	}
	if len(policy.AllowPrivateHostSuffixes) != 1 || policy.AllowPrivateHostSuffixes[0] != "svc.cluster.local" {
		t.Errorf("unexpected allow_private_host_suffixes: %v", policy.AllowPrivateHostSuffixes)
	}
	if policy.AllowIPLiterals {
		t.Error("expected allow_ip_literals=false")
	}
}

func TestLoad_SSRF_InvalidRoutePolicyRef_Fails(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
[outbound_http.ssrf]
mode = "strict"
route_policy = "nonexistent"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error for invalid route_policy reference")
	}
	if !strings.Contains(err.Error(), "nonexistent") {
		t.Errorf("expected error mentioning policy name, got: %v", err)
	}
}

func TestLoad_SSRF_UnsupportedRedirectMode_Fails(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{"formerly valid value", "same-host"},
		{"invalid value", "follow-all"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			configPath := filepath.Join(dir, "config.toml")

			tomlContent := `
[outbound_http.ssrf]
mode = "strict"
redirect_mode = "` + tt.value + `"
`
			if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
				t.Fatalf("failed to write config: %v", err)
			}

			_, err := Load(LoaderOptions{ConfigPath: configPath})
			if err == nil {
				t.Fatal("expected error: outbound_http.ssrf.redirect_mode is unsupported")
			}
			if !strings.Contains(err.Error(), "unsupported keys") {
				t.Errorf("expected generic unsupported-keys error, got: %v", err)
			}
			if !strings.Contains(err.Error(), "outbound_http.ssrf.redirect_mode") {
				t.Errorf("expected error mentioning outbound_http.ssrf.redirect_mode, got: %v", err)
			}
		})
	}
}

func TestLoad_SSRF_UnsupportedDNSResolution_Fails(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{"formerly valid value", "all-records"},
		{"invalid value", "first-record"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			configPath := filepath.Join(dir, "config.toml")

			tomlContent := `
[outbound_http.ssrf]
mode = "strict"
dns_resolution = "` + tt.value + `"
`
			if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
				t.Fatalf("failed to write config: %v", err)
			}

			_, err := Load(LoaderOptions{ConfigPath: configPath})
			if err == nil {
				t.Fatal("expected error: outbound_http.ssrf.dns_resolution is unsupported")
			}
			if !strings.Contains(err.Error(), "unsupported keys") {
				t.Errorf("expected generic unsupported-keys error, got: %v", err)
			}
			if !strings.Contains(err.Error(), "outbound_http.ssrf.dns_resolution") {
				t.Errorf("expected error mentioning outbound_http.ssrf.dns_resolution, got: %v", err)
			}
		})
	}
}

func TestLoad_SSRF_NoneScope_RejectsOff(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := configfixture.NoneScopeBase() + configfixture.SSRFOff()
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error: compatibility_scope=none must reject ssrf.mode=off")
	}
	if !strings.Contains(err.Error(), "compatibility_scope=none requires outbound_http.ssrf.mode=strict") {
		t.Errorf("expected none+off rejection error, got: %v", err)
	}
}

func TestLoad_SSRF_NoneScope_StrictWithValidRoutePolicy_Loads(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	// strict preset satisfies all compatibility_scope=none guardrails, so
	// a valid route policy under mode=strict must load without error.
	tomlContent := configfixture.NoneScopeBase() +
		configfixture.SSRFStrictWithPolicy("internal") +
		configfixture.RoutePolicyInternal("internal")
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v; none + strict + valid route policy must load cleanly", err)
	}
	if cfg.OutboundHTTP.SSRF.Mode != "strict" {
		t.Errorf("expected outbound_http.ssrf.mode %q, got %q", "strict", cfg.OutboundHTTP.SSRF.Mode)
	}
	if cfg.OutboundHTTP.SSRF.RoutePolicy != "internal" {
		t.Errorf("expected outbound_http.ssrf.route_policy %q, got %q", "internal", cfg.OutboundHTTP.SSRF.RoutePolicy)
	}
}

func TestLoad_SSRF_NoneScope_RoutePolicyWithIPLiterals_Fails(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := configfixture.NoneScopeBase() +
		configfixture.SSRFStrictWithPolicy("internal") +
		configfixture.RoutePolicyInternalIPLiteralsTrue("internal")
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error: allow_ip_literals=true forbidden under compatibility_scope=none")
	}
	if !strings.Contains(err.Error(), "allow_ip_literals=false") {
		t.Errorf("expected allow_ip_literals error, got: %v", err)
	}
}

func TestLoad_SSRF_NoneScope_RoutePolicyWithCatchAllCIDR_Fails(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := configfixture.NoneScopeBase() +
		configfixture.SSRFStrictWithPolicy("catchall") +
		configfixture.RoutePolicyCatchAll("catchall")
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error: catch-all CIDR 0.0.0.0/0 forbidden under compatibility_scope=none")
	}
	if !strings.Contains(err.Error(), "0.0.0.0/0") {
		t.Errorf("expected catch-all CIDR error, got: %v", err)
	}
}

func TestLoad_SSRF_NoneScope_RoutePolicyMissingHostSuffixes_Fails(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := configfixture.NoneScopeBase() +
		configfixture.SSRFStrictWithPolicy("minimal") +
		configfixture.RoutePolicyMinimalNoSuffixes("minimal")
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error: empty allow_private_host_suffixes forbidden under compatibility_scope=none")
	}
	if !strings.Contains(err.Error(), "allow_private_host_suffixes") {
		t.Errorf("expected host suffixes error, got: %v", err)
	}
}

func TestLoad_SSRF_NoneScope_RoutePolicyWithInvalidCIDR_Fails(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := configfixture.NoneScopeBase() +
		configfixture.SSRFStrictWithPolicy("internal") +
		configfixture.RoutePolicyInternalInvalidCIDR("internal")
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error: invalid CIDR in allow_private_cidrs should be rejected")
	}
	if !strings.Contains(err.Error(), "invalid CIDR") {
		t.Errorf("expected invalid CIDR error, got: %v", err)
	}
}

func TestLoad_SSRF_NoneScope_RoutePolicyWithInvalidPort_Fails(t *testing.T) {
	tests := []struct {
		name        string
		port        string
		wantContain string
	}{
		{
			name:        "port zero",
			port:        "0",
			wantContain: "invalid port",
		},
		{
			name:        "port above max",
			port:        "65536",
			wantContain: "invalid port",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			configPath := filepath.Join(dir, "config.toml")

			tomlContent := configfixture.NoneScopeBase() +
				configfixture.SSRFStrictWithPolicy("internal") +
				configfixture.RoutePolicyInternalWithPort("internal", tc.port)
			if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
				t.Fatalf("failed to write config: %v", err)
			}

			_, err := Load(LoaderOptions{ConfigPath: configPath})
			if err == nil {
				t.Fatalf("expected error for port %s: should be rejected as out of range", tc.port)
			}
			if !strings.Contains(err.Error(), tc.wantContain) {
				t.Errorf("expected %q in error, got: %v", tc.wantContain, err)
			}
		})
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
	interopCfg := CompatConfig()
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
	// Strict mode: enabled=true, path=token, require_token_exchange=true
	strictCfg := StrictConfig()
	if strictCfg.TokenExchange.Enabled == nil || !*strictCfg.TokenExchange.Enabled {
		t.Error("expected strict mode token_exchange.enabled true")
	}
	if strictCfg.TokenExchange.Path != "token" {
		t.Errorf("expected strict mode token_exchange.path 'token', got %q", strictCfg.TokenExchange.Path)
	}
	if !strictCfg.RequireTokenExchange {
		t.Error("expected strict mode require_token_exchange true")
	}

	// Interop mode: enabled=true, path=token, require_token_exchange=false
	interopCfg := CompatConfig()
	if interopCfg.TokenExchange.Enabled == nil || !*interopCfg.TokenExchange.Enabled {
		t.Error("expected interop mode token_exchange.enabled true")
	}
	if interopCfg.TokenExchange.Path != "token" {
		t.Errorf("expected interop mode token_exchange.path 'token', got %q", interopCfg.TokenExchange.Path)
	}
	if interopCfg.RequireTokenExchange {
		t.Error("expected interop mode require_token_exchange false")
	}

	// Dev mode: enabled=true, path=token, require_token_exchange=false
	devCfg := DevConfig()
	if devCfg.TokenExchange.Enabled == nil || !*devCfg.TokenExchange.Enabled {
		t.Error("expected dev mode token_exchange.enabled true")
	}
	if devCfg.TokenExchange.Path != "token" {
		t.Errorf("expected dev mode token_exchange.path 'token', got %q", devCfg.TokenExchange.Path)
	}
	if devCfg.RequireTokenExchange {
		t.Error("expected dev mode require_token_exchange false")
	}
}

func TestLoad_TokenExchangeConfig_FromTOML(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
mode = "compat"
require_token_exchange = false

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

func TestLoad_RequireTokenExchange_FromTOML(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
mode = "compat"
require_token_exchange = false
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.RequireTokenExchange {
		t.Error("expected require_token_exchange false from TOML")
	}
}

func TestLoad_RequireTokenExchange_FlagsOverrideTOML(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
mode = "compat"
require_token_exchange = true
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	require := "false"
	cfg, err := Load(LoaderOptions{
		ConfigPath: configPath,
		FlagOverrides: FlagOverrides{
			RequireTokenExchange: &require,
		},
	})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.RequireTokenExchange {
		t.Error("expected require_token_exchange false from flag")
	}
}

func TestLoad_WebDAVTokenExchangeSurface_UnsupportedFails(t *testing.T) {
	tests := []struct {
		name   string
		config string
	}{
		{
			name: "unsupported table",
			config: `
mode = "strict"
[webdav_token_exchange]
mode = "strict"
`,
		},
		{
			name: "unsupported dotted key",
			config: `
mode = "strict"
webdav_token_exchange.mode = "strict"
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
				t.Fatal("expected unsupported webdav_token_exchange surface to fail")
			}
			if !strings.Contains(err.Error(), "webdav_token_exchange") {
				t.Fatalf("expected error to mention webdav_token_exchange, got %v", err)
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

func TestLoad_ExternalOrigin_UnsupportedFails(t *testing.T) {
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
		t.Fatal("expected error for unsupported external_origin key")
	}
	if !strings.Contains(err.Error(), "external_origin") {
		t.Errorf("expected error to mention external_origin, got: %v", err)
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

func TestLoad_TLSDir_Absent_NoChange(t *testing.T) {
	// No tls_dir in TOML; paths stay at preset defaults
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	tomlContent := `mode = "strict"
public_origin = "https://localhost:9200"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.TLS.TLSDir != "" {
		t.Errorf("expected TLSDir empty when absent, got %q", cfg.TLS.TLSDir)
	}
	if cfg.TLS.SelfSignedDir != ".ocm/certs" {
		t.Errorf("expected SelfSignedDir .ocm/certs from preset, got %q", cfg.TLS.SelfSignedDir)
	}
	if cfg.TLS.ACME.StorageDir != ".ocm/acme" {
		t.Errorf("expected ACME StorageDir .ocm/acme from preset, got %q", cfg.TLS.ACME.StorageDir)
	}
	if cfg.Signature.KeyPath != ".ocm/keys/signing.pem" {
		t.Errorf("expected Signature KeyPath .ocm/keys/signing.pem from preset, got %q", cfg.Signature.KeyPath)
	}
}

func TestLoad_TLSDir_NotInTOML_NoDerivation(t *testing.T) {
	// Even with [tls] present, derivation must not run unless tls_dir key is present.
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	tomlContent := `mode = "strict"
public_origin = "https://localhost:9200"

[tls]
mode = "selfsigned"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.TLS.TLSDir != "" {
		t.Errorf("expected TLSDir empty when tls_dir key is absent, got %q", cfg.TLS.TLSDir)
	}
	if cfg.TLS.SelfSignedDir != ".ocm/certs" {
		t.Errorf("expected preset SelfSignedDir .ocm/certs, got %q", cfg.TLS.SelfSignedDir)
	}
	if cfg.TLS.ACME.StorageDir != ".ocm/acme" {
		t.Errorf("expected preset ACME StorageDir .ocm/acme, got %q", cfg.TLS.ACME.StorageDir)
	}
	if cfg.Signature.KeyPath != ".ocm/keys/signing.pem" {
		t.Errorf("expected preset Signature KeyPath .ocm/keys/signing.pem, got %q", cfg.Signature.KeyPath)
	}
}

func TestLoad_TLSDir_Present_DerivesDefaults(t *testing.T) {
	// tls_dir set; derives self_signed_dir, acme.storage_dir, signature.key_path
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	tomlContent := `mode = "strict"
public_origin = "https://localhost:9200"

[tls]
tls_dir = "/data/tls"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.TLS.TLSDir != "/data/tls" {
		t.Errorf("expected TLSDir /data/tls, got %q", cfg.TLS.TLSDir)
	}
	if cfg.TLS.SelfSignedDir != "/data/tls/certs" {
		t.Errorf("expected SelfSignedDir /data/tls/certs, got %q", cfg.TLS.SelfSignedDir)
	}
	if cfg.TLS.ACME.StorageDir != "/data/tls/acme" {
		t.Errorf("expected ACME StorageDir /data/tls/acme, got %q", cfg.TLS.ACME.StorageDir)
	}
	if cfg.Signature.KeyPath != "/data/tls/keys/signing.pem" {
		t.Errorf("expected Signature KeyPath /data/tls/keys/signing.pem, got %q", cfg.Signature.KeyPath)
	}
}

func TestLoad_TLSDir_ExplicitOverride(t *testing.T) {
	// tls_dir set but self_signed_dir also explicitly set; uses explicit value
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	tomlContent := `mode = "strict"
public_origin = "https://localhost:9200"

[tls]
tls_dir = "/data/tls"
self_signed_dir = "/custom/certs"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.TLS.SelfSignedDir != "/custom/certs" {
		t.Errorf("expected explicit SelfSignedDir /custom/certs, got %q", cfg.TLS.SelfSignedDir)
	}
	if cfg.TLS.ACME.StorageDir != "/data/tls/acme" {
		t.Errorf("expected derived ACME StorageDir /data/tls/acme, got %q", cfg.TLS.ACME.StorageDir)
	}
}

func TestLoad_TLSDir_EmptyString_Fails(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	tomlContent := `mode = "strict"
public_origin = "https://localhost:9200"

[tls]
tls_dir = ""
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected Load to fail when tls_dir is empty string")
	}
	if !strings.Contains(err.Error(), "tls.tls_dir is set but empty") {
		t.Errorf("expected error about tls_dir empty, got %v", err)
	}
}

func TestLoad_TLSDir_WhitespaceOnly_Fails(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	tomlContent := `mode = "strict"
public_origin = "https://localhost:9200"

[tls]
tls_dir = "   "
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected Load to fail when tls_dir is whitespace only")
	}
	if !strings.Contains(err.Error(), "tls.tls_dir is set but empty") {
		t.Errorf("expected error about tls_dir empty, got %v", err)
	}
}

func TestLoad_TLSRootCAFile_Valid(t *testing.T) {
	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caFile, []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n"), 0644); err != nil {
		t.Fatalf("failed to write CA file: %v", err)
	}
	configPath := filepath.Join(dir, "config.toml")
	tomlContent := `mode = "strict"
public_origin = "https://localhost:9200"

[outbound_http]
tls_root_ca_file = "` + caFile + `"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.OutboundHTTP.TLSRootCAFile != caFile {
		t.Errorf("expected TLSRootCAFile %q, got %q", caFile, cfg.OutboundHTTP.TLSRootCAFile)
	}
}

func TestLoad_TLSRootCAFile_Missing_Fails(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	tomlContent := `mode = "strict"
public_origin = "https://localhost:9200"

[outbound_http]
tls_root_ca_file = "/nonexistent/ca.pem"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected Load to fail when tls_root_ca_file path does not exist")
	}
	if !strings.Contains(err.Error(), "tls_root_ca_file") {
		t.Errorf("expected error to mention tls_root_ca_file, got %v", err)
	}
}

func TestLoad_ProxyURL_ValidValues(t *testing.T) {
	tests := []struct {
		name     string
		proxyURL string
	}{
		{"standard http proxy", "http://mitm:8080"},
		{"https proxy", "https://proxy.example.com:3128"},
		{"ip proxy", "http://192.168.1.1:8080"},
		{"loopback allowed", "http://127.0.0.1:8080"},
		{"private loopback name", "http://mitm.local:8080"},
		{"no path", "http://proxy.example.com"},
		{"empty no proxy", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			configPath := filepath.Join(dir, "config.toml")

			tomlContent := `mode = "strict"
`
			if tt.proxyURL != "" {
				tomlContent += `
[outbound_http]
proxy_url = "` + tt.proxyURL + `"
`
			}
			if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
				t.Fatalf("failed to write config: %v", err)
			}

			cfg, err := Load(LoaderOptions{ConfigPath: configPath})
			if err != nil {
				t.Fatalf("Load() unexpected error for proxy_url %q: %v", tt.proxyURL, err)
			}
			if cfg.OutboundHTTP.ProxyURL != tt.proxyURL {
				t.Errorf("expected ProxyURL %q, got %q", tt.proxyURL, cfg.OutboundHTTP.ProxyURL)
			}
		})
	}
}

func TestLoad_ProxyURL_InvalidValues(t *testing.T) {
	tests := []struct {
		name      string
		proxyURL  string
		wantInErr string
	}{
		{
			name:      "ftp scheme",
			proxyURL:  "ftp://proxy.example.com:21",
			wantInErr: "proxy_url",
		},
		{
			name:      "userinfo present",
			proxyURL:  "http://user:pass@proxy.example.com:8080",
			wantInErr: "proxy_url",
		},
		{
			name:      "empty host with port",
			proxyURL:  "http://:8080",
			wantInErr: "proxy_url",
		},
		{
			name:      "no scheme",
			proxyURL:  "proxy.example.com:8080",
			wantInErr: "proxy_url",
		},
		{
			name:      "username only no password",
			proxyURL:  "http://user@proxy.example.com:8080",
			wantInErr: "proxy_url",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			configPath := filepath.Join(dir, "config.toml")

			tomlContent := `mode = "strict"

[outbound_http]
proxy_url = "` + tt.proxyURL + `"
`
			if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
				t.Fatalf("failed to write config: %v", err)
			}

			_, err := Load(LoaderOptions{ConfigPath: configPath})
			if err == nil {
				t.Fatalf("Load() expected error for proxy_url %q, got nil", tt.proxyURL)
			}
			if !strings.Contains(err.Error(), tt.wantInErr) {
				t.Errorf("expected error to contain %q, got: %v", tt.wantInErr, err)
			}
		})
	}
}

func TestLoad_ProxyURL_StrictModeAllowsLoopback(t *testing.T) {
	// Under compatibility_scope=none the proxy host is operator-trusted;
	// loopback and private addresses must be accepted for proxy_url.
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `mode = "strict"

[outbound_http]
proxy_url = "http://127.0.0.1:8080"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v (loopback must be allowed for proxy under compatibility_scope=none)", err)
	}
	if cfg.OutboundHTTP.ProxyURL != "http://127.0.0.1:8080" {
		t.Errorf("expected ProxyURL http://127.0.0.1:8080, got %q", cfg.OutboundHTTP.ProxyURL)
	}
}

func TestLoad_ProxyURL_DefaultEmpty(t *testing.T) {
	// No proxy_url in config or flags; field must default to empty string.
	cfg, err := Load(LoaderOptions{})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.OutboundHTTP.ProxyURL != "" {
		t.Errorf("expected ProxyURL empty by default, got %q", cfg.OutboundHTTP.ProxyURL)
	}
}

func TestProxyEnvFallback_StrictPresetDefaultTrue(t *testing.T) {
	cfg := StrictConfig()
	if !cfg.OutboundHTTP.ProxyEnvFallback {
		t.Error("strict preset must default proxy_env_fallback=true")
	}
}

func TestProxyEnvFallback_CompatPresetDefaultTrue(t *testing.T) {
	cfg := CompatConfig()
	if !cfg.OutboundHTTP.ProxyEnvFallback {
		t.Error("compat preset must default proxy_env_fallback=true")
	}
}

func TestProxyEnvFallback_DevPresetDefaultFalse(t *testing.T) {
	cfg := DevConfig()
	if cfg.OutboundHTTP.ProxyEnvFallback {
		t.Error("dev preset must default proxy_env_fallback=false")
	}
}

func TestProxyEnvFallback_ExplicitTOMLTrueOverridesDevPreset(t *testing.T) {
	// dev preset defaults proxy_env_fallback=false; explicit true in TOML must override it.
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	tomlContent := `mode = "dev"

[outbound_http]
proxy_env_fallback = true
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}
	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.OutboundHTTP.ProxyEnvFallback {
		t.Error("explicit proxy_env_fallback=true in TOML must override the dev preset default (false)")
	}
}

func TestProxyEnvFallback_ExplicitTOMLFalse(t *testing.T) {
	// strict preset defaults true; explicit false in TOML must override it.
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	tomlContent := `mode = "strict"

[outbound_http]
proxy_env_fallback = false
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}
	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.OutboundHTTP.ProxyEnvFallback {
		t.Error("explicit proxy_env_fallback=false in TOML must override the strict preset default")
	}
}

func TestProxyEnvFallback_OmittedTOMLPreservesPreset(t *testing.T) {
	// [outbound_http] section present but proxy_env_fallback not set;
	// the strict preset value (true) must be preserved.
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	tomlContent := `mode = "strict"

[outbound_http]
timeout_ms = 8000
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}
	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.OutboundHTTP.ProxyEnvFallback {
		t.Error("omitted proxy_env_fallback in TOML must preserve the strict preset default (true)")
	}
}

func TestProxyEnvFallback_ProxyURLPrecedence(t *testing.T) {
	// When proxy_url is set alongside proxy_env_fallback=true, both fields
	// may coexist in the config contract; proxy_url takes precedence at the
	// HTTP client level (env vars are not consulted when an explicit URL is set).
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	tomlContent := `mode = "strict"

[outbound_http]
proxy_url = "http://explicit.proxy:8080"
proxy_env_fallback = true
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}
	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.OutboundHTTP.ProxyURL != "http://explicit.proxy:8080" {
		t.Errorf("expected ProxyURL http://explicit.proxy:8080, got %q", cfg.OutboundHTTP.ProxyURL)
	}
	if !cfg.OutboundHTTP.ProxyEnvFallback {
		t.Error("proxy_env_fallback should remain true when proxy_url is also set")
	}
}

func TestOutboundHTTPConfigStrict_ProxyEnvFallbackFalse(t *testing.T) {
	// OutboundHTTPConfigStrict is a non-ambient building block: it must never
	// enable environment-based proxy discovery on its own.  StrictConfig() may
	// layer proxy_env_fallback=true on top, but the raw builder must stay false
	// so callers that use it directly get a safe, non-ambient default.
	cfg := OutboundHTTPConfigStrict()
	if cfg.ProxyEnvFallback {
		t.Error("OutboundHTTPConfigStrict() must return ProxyEnvFallback=false (non-ambient by default)")
	}
}

func TestSSRFRoutePolicyGuardrails_BlankHostSuffix_NoneScope(t *testing.T) {
	tests := []struct {
		name     string
		suffixes string
	}{
		{"empty string entry", `[""]`},
		{"whitespace-only entry", `["   "]`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			configPath := filepath.Join(dir, "config.toml")
			tomlContent := `mode = "strict"

[outbound_http.ssrf]
route_policy = "myp"

[outbound_http.ssrf.route_policies.myp]
allow_private_host_suffixes = ` + tt.suffixes + `
allow_private_cidrs = ["10.0.0.0/8"]
allowed_ports = [8080]
allow_ip_literals = false
`
			if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
				t.Fatalf("failed to write config: %v", err)
			}

			_, err := Load(LoaderOptions{ConfigPath: configPath})
			if err == nil {
				t.Fatal("expected error for blank entry in allow_private_host_suffixes under compatibility_scope=none")
			}
			if !strings.Contains(err.Error(), "allow_private_host_suffixes") {
				t.Errorf("expected error to mention allow_private_host_suffixes, got: %v", err)
			}
			if !strings.Contains(err.Error(), "compatibility_scope=none") {
				t.Errorf("expected error to mention compatibility_scope=none, got: %v", err)
			}
		})
	}
}

func TestSSRFRoutePolicyGuardrails_BlankHostSuffix_ScopedScope(t *testing.T) {
	tests := []struct {
		name     string
		suffixes string
	}{
		{"empty string entry", `[""]`},
		{"whitespace-only entry", `["   "]`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			configPath := filepath.Join(dir, "config.toml")
			tomlContent := configfixture.ScopedScopeBase() +
				configfixture.SSRFRoutePolicyRef("myp") +
				configfixture.RoutePolicyWithBlankSuffix("myp", tt.suffixes)
			if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
				t.Fatalf("failed to write config: %v", err)
			}

			_, err := Load(LoaderOptions{ConfigPath: configPath})
			if err == nil {
				t.Fatal("expected error for blank entry in allow_private_host_suffixes under compatibility_scope=scoped")
			}
			if !strings.Contains(err.Error(), "allow_private_host_suffixes") {
				t.Errorf("expected error to mention allow_private_host_suffixes, got: %v", err)
			}
			if !strings.Contains(err.Error(), "compatibility_scope=scoped") {
				t.Errorf("expected error to mention compatibility_scope=scoped, got: %v", err)
			}
		})
	}
}

func TestLoad_TLSRootCADir_NotDirectory_Fails(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(filePath, []byte("x"), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}
	configPath := filepath.Join(dir, "config.toml")
	tomlContent := `mode = "strict"
public_origin = "https://localhost:9200"

[outbound_http]
tls_root_ca_dir = "` + filePath + `"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected Load to fail when tls_root_ca_dir path is not a directory")
	}
	if !strings.Contains(err.Error(), "tls_root_ca_dir") {
		t.Errorf("expected error to mention tls_root_ca_dir, got %v", err)
	}
}
