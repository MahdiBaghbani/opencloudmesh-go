package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
