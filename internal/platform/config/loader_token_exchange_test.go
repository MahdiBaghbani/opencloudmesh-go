// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTokenExchangeConfig_DefaultsPerMode(t *testing.T) {
	strictCfg := StrictConfig()
	if strictCfg.TokenExchange.Path != "token" {
		t.Errorf("expected strict mode token_exchange.path 'token', got %q", strictCfg.TokenExchange.Path)
	}

	devCfg := DevConfig()
	if devCfg.TokenExchange.Path != "token" {
		t.Errorf("expected dev mode token_exchange.path 'token', got %q", devCfg.TokenExchange.Path)
	}
}

func TestLoad_TokenExchangeConfig_FromTOML(t *testing.T) {
	// Clear ambient env override so the token exchange load is deterministic.
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
mode = "dev"

[token_exchange]
path = "token/v2"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.TokenExchange.Path != "token/v2" {
		t.Errorf("expected token_exchange.path 'token/v2', got %q", cfg.TokenExchange.Path)
	}
}

func TestLoad_TokenExchangeConfig_FlagOverridesTOMLPath(t *testing.T) {
	// Clear ambient env override so the flag-over-TOML precedence is deterministic.
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
mode = "strict"

[token_exchange]
path = "token/v2"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	path := "exchange"

	cfg, err := Load(LoaderOptions{
		ConfigPath: configPath,
		FlagOverrides: FlagOverrides{
			TokenExchangePath: &path,
		},
	})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
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
			// Clear ambient env override so the invalid-path validation is deterministic.
			t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")
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

func TestLoad_TokenExchangeConfig_DefaultPathWhenSectionMissing(t *testing.T) {
	// Clear ambient env override so the default path load is deterministic.
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")

	cfg, err := Load(LoaderOptions{})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.TokenExchange.Path != "token" {
		t.Errorf("expected token_exchange.path 'token' by default, got %q", cfg.TokenExchange.Path)
	}
}
