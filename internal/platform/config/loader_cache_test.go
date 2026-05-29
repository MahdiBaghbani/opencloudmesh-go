package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
