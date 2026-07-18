package config

import (
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
		{"compat rejected", "compat", "", true},
		{"dev", "dev", ModeDev, false},
		{"empty defaults to strict", "", ModeStrict, false},
		{"uppercase", "STRICT", ModeStrict, false},
		{"mixed case compat rejected", "Compat", "", true},
		{"whitespace", "  dev  ", ModeDev, false},
		{"invalid", "invalid", "", true},
		{"interop rejected", "interop", "", true},
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
			if tt.wantErr && tt.input == "compat" && !strings.Contains(err.Error(), "must be one of strict, dev") {
				t.Errorf("ParseMode(compat) error = %v, want strict/dev allowed-values message", err)
			}
		})
	}
}

func TestLoad_NoConfigFile(t *testing.T) {
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
}

func TestLoad_ModeFlag(t *testing.T) {
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
	tomlContent := `
mode = "dev"
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
	configPath := writeTempConfig(t, tomlContent)

	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Mode != "dev" {
		t.Errorf("expected mode dev, got %s", cfg.Mode)
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
	if cfg.OutboundHTTP.SSRF.Mode != "strict" {
		t.Errorf("expected SSRF mode strict from TOML, got %s", cfg.OutboundHTTP.SSRF.Mode)
	}
	if cfg.OutboundHTTP.TimeoutMS != 5000 {
		t.Errorf("expected timeout 5000, got %d", cfg.OutboundHTTP.TimeoutMS)
	}
}

func TestLoad_Precedence_FlagsOverrideConfigFile(t *testing.T) {
	tomlContent := `
mode = "dev"
public_origin = "https://from-toml.com"
listen_addr = ":9000"
`
	configPath := writeTempConfig(t, tomlContent)

	origin := "https://from-flag.com"
	cfg, err := Load(LoaderOptions{
		ConfigPath: configPath,
		FlagOverrides: FlagOverrides{
			PublicOrigin: &origin,
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
}

func TestLoad_ModeFlag_OverridesConfigFileMode(t *testing.T) {
	tomlContent := `
mode = "dev"
`
	configPath := writeTempConfig(t, tomlContent)

	cfg, err := Load(LoaderOptions{
		ConfigPath: configPath,
		ModeFlag:   "strict",
	})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Mode != "strict" {
		t.Errorf("expected mode strict from flag, got %s", cfg.Mode)
	}
	if cfg.OutboundHTTP.SSRF.Mode != "strict" {
		t.Errorf("expected SSRF mode strict from strict preset, got %s", cfg.OutboundHTTP.SSRF.Mode)
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
	configPath := writeTempConfig(t, "this is not valid toml [[[")

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error for invalid TOML")
	}
	if !strings.Contains(err.Error(), "failed to parse config file") {
		t.Errorf("expected parse error, got: %v", err)
	}
}

func TestLoad_InvalidMode_FailsFast(t *testing.T) {
	invalidModes := []string{"invalid", "interop", "compat"}
	for _, mode := range invalidModes {
		_, err := Load(LoaderOptions{ModeFlag: mode})
		if err == nil {
			t.Errorf("Load(ModeFlag=%q): expected error for invalid mode", mode)
			continue
		}
		if !strings.Contains(err.Error(), "invalid mode") {
			t.Errorf("Load(ModeFlag=%q): expected mode error, got: %v", mode, err)
		}
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
	if cfg.OutboundHTTP.InsecureSkipVerify {
		t.Error("expected InsecureSkipVerify false in strict")
	}
	if cfg.OutboundHTTP.MaxRedirects != 1 {
		t.Errorf("expected MaxRedirects 1 in strict, got %d", cfg.OutboundHTTP.MaxRedirects)
	}
	if cfg.PeerPolicy != "strict" {
		t.Errorf("expected peer_policy strict in strict config, got %q", cfg.PeerPolicy)
	}
	if !cfg.TokenExchangeEnabled() {
		t.Error("expected token exchange enabled in strict config")
	}
}

func TestDevConfig(t *testing.T) {
	cfg := DevConfig()

	if cfg.Mode != "dev" {
		t.Errorf("expected mode dev, got %s", cfg.Mode)
	}
	if cfg.CompatibilityScope != "scoped" {
		t.Errorf("expected compatibility scope scoped, got %s", cfg.CompatibilityScope)
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
	if cfg.PeerPolicy != "strict" {
		t.Errorf("expected peer_policy strict in dev, got %q", cfg.PeerPolicy)
	}
	if !cfg.TokenExchangeEnabled() {
		t.Error("expected token exchange enabled in dev")
	}
}

// TestDevConfig_DerivesFromStrict pins the behavior-preserving contract for
// DevConfig now that it overlays StrictConfig.
func TestDevConfig_DerivesFromStrict(t *testing.T) {
	dev := DevConfig()
	strict := StrictConfig()

	deltas := []struct {
		name string
		got  any
		want any
	}{
		{"Mode", dev.Mode, "dev"},
		{"CompatibilityScope", dev.CompatibilityScope, "scoped"},
		{"TLS.Mode", dev.TLS.Mode, "off"},
		{"TLS.ACME.Directory", dev.TLS.ACME.Directory, "https://acme-staging-v02.api.letsencrypt.org/directory"},
		{"TLS.ACME.UseStaging", dev.TLS.ACME.UseStaging, true},
		{"OutboundHTTP.SSRF.Mode", dev.OutboundHTTP.SSRF.Mode, "off"},
		{"OutboundHTTP.MaxRedirects", dev.OutboundHTTP.MaxRedirects, 3},
		{"OutboundHTTP.InsecureSkipVerify", dev.OutboundHTTP.InsecureSkipVerify, true},
		{"OutboundHTTP.ProxyEnvFallback", dev.OutboundHTTP.ProxyEnvFallback, false},
		{"Logging.Level", dev.Logging.Level, "debug"},
	}
	for _, d := range deltas {
		if d.got != d.want {
			t.Errorf("dev delta %s = %v, want %v", d.name, d.got, d.want)
		}
	}

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
		{"TokenExchange.Path", dev.TokenExchange.Path, strict.TokenExchange.Path},
		{"PeerPolicy", dev.PeerPolicy, strict.PeerPolicy},
	}
	for _, i := range inherited {
		if i.got != i.want {
			t.Errorf("dev inherited %s = %v, want strict value %v", i.name, i.got, i.want)
		}
	}

	if got := strings.Join(dev.Server.TrustedProxies, ","); got != strings.Join(strict.Server.TrustedProxies, ",") {
		t.Errorf("dev TrustedProxies = %v, want strict value %v", dev.Server.TrustedProxies, strict.Server.TrustedProxies)
	}

	if dev.TokenExchange.Enabled == nil || !*dev.TokenExchange.Enabled {
		t.Fatal("expected dev token_exchange.enabled pointer to be non-nil true")
	}

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
