package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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

func TestLoad_PeerPolicy_DefaultIsStrict(t *testing.T) {
	cfg, err := Load(LoaderOptions{})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.PeerPolicy != "strict" {
		t.Errorf("expected default peer_policy strict, got %q", cfg.PeerPolicy)
	}
}
