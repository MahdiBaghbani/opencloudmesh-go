package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoad_OCMDiffDiscovery_DefaultOmitted(t *testing.T) {
	// Clear ambient env override so the discovery default load is deterministic.
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")

	cfg, err := Load(LoaderOptions{})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.OCM.Discovery.PeerAPIVersionPolicy != "accept-any" {
		t.Errorf("policy = %q, want accept-any", cfg.OCM.Discovery.PeerAPIVersionPolicy)
	}

	if cfg.OCM.Discovery.PeerAPIVersionWarn != "any-diff" {
		t.Errorf("warn = %q, want any-diff", cfg.OCM.Discovery.PeerAPIVersionWarn)
	}
}

func TestLoad_OCMDiffDiscovery_ExplicitEmptyDefaults(t *testing.T) {
	// Clear ambient env override so the explicit-empty load is deterministic.
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
mode = "dev"

[ocm.discovery]
peer_api_version_policy = ""
peer_api_version_warn = ""
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.OCM.Discovery.PeerAPIVersionPolicy != "accept-any" {
		t.Errorf("policy = %q, want accept-any", cfg.OCM.Discovery.PeerAPIVersionPolicy)
	}

	if cfg.OCM.Discovery.PeerAPIVersionWarn != "any-diff" {
		t.Errorf("warn = %q, want any-diff", cfg.OCM.Discovery.PeerAPIVersionWarn)
	}
}

func TestLoad_OCMDiffDiscovery_ValidEnumCombinations(t *testing.T) {
	policies := []string{"accept-any", "exact", "at-least-1.4"}
	warns := []string{"any-diff", "lower-only", "none"}

	for _, policy := range policies {
		for _, warn := range warns {
			t.Run(policy+"/"+warn, func(t *testing.T) {
				// Clear ambient env override so each enum combination load is deterministic.
				t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")
				dir := t.TempDir()
				configPath := filepath.Join(dir, "config.toml")

				tomlContent := `
mode = "dev"

[ocm.discovery]
peer_api_version_policy = "` + policy + `"
peer_api_version_warn = "` + warn + `"
`
				if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
					t.Fatalf("write config: %v", err)
				}

				cfg, err := Load(LoaderOptions{ConfigPath: configPath})
				if err != nil {
					t.Fatalf("Load() error = %v", err)
				}

				if cfg.OCM.Discovery.PeerAPIVersionPolicy != policy {
					t.Errorf("policy = %q, want %q", cfg.OCM.Discovery.PeerAPIVersionPolicy, policy)
				}

				if cfg.OCM.Discovery.PeerAPIVersionWarn != warn {
					t.Errorf("warn = %q, want %q", cfg.OCM.Discovery.PeerAPIVersionWarn, warn)
				}
			})
		}
	}
}

func TestLoad_OCMDiffDiscovery_InvalidPolicy(t *testing.T) {
	// Clear ambient env override so the validation error path is deterministic.
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
mode = "dev"

[ocm.discovery]
peer_api_version_policy = "maybe"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("Load() should fail for invalid policy")
	}

	if !strings.Contains(err.Error(), "peer_api_version_policy") {
		t.Fatalf("expected policy error, got: %v", err)
	}
}

func TestLoad_OCMDiffDiscovery_InvalidWarn(t *testing.T) {
	// Clear ambient env override so the validation error path is deterministic.
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
mode = "dev"

[ocm.discovery]
peer_api_version_warn = "sometimes"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("Load() should fail for invalid warn mode")
	}

	if !strings.Contains(err.Error(), "peer_api_version_warn") {
		t.Fatalf("expected warn error, got: %v", err)
	}
}
