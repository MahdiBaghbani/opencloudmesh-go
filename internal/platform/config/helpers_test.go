package config

import (
	"os"
	"path/filepath"
	"testing"
)

// writeTempConfig writes toml to a config.toml file inside a fresh per-test
// temp dir and returns its path. It centralizes the temp-dir + write-config
// boilerplate shared across loader tests.
func writeTempConfig(t *testing.T, toml string) string {
	t.Helper()
	configPath := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(configPath, []byte(toml), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}
	return configPath
}
