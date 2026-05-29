package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
