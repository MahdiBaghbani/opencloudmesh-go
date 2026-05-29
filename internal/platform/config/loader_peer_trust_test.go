package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
