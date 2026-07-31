// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestPersistencePresetDefaults verifies that both mode presets default
// to the memory backend so that memory is a first-class choice, not a
// hidden fallback.
func TestPersistencePresetDefaults(t *testing.T) {
	presets := []struct {
		name string
		fn   func() *Config
	}{
		{"strict", StrictConfig},
		{"dev", DevConfig},
	}

	for _, p := range presets {
		t.Run(p.name, func(t *testing.T) {
			cfg := p.fn()
			if cfg.Persistence.Backend != BackendMemory {
				t.Errorf("%s preset: expected Backend=%q, got %q",
					p.name, BackendMemory, cfg.Persistence.Backend)
			}
		})
	}
}

// TestPersistenceLoad_DefaultsToMemory verifies that Load() without a config
// file returns the memory backend (strict preset default).
func TestPersistenceLoad_DefaultsToMemory(t *testing.T) {
	// Clear ambient env override so the default backend load is deterministic.
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")

	cfg, err := Load(LoaderOptions{})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Persistence.Backend != BackendMemory {
		t.Errorf("expected Backend=%q, got %q", BackendMemory, cfg.Persistence.Backend)
	}

	if cfg.Persistence.DataDir != "" {
		t.Errorf("expected empty DataDir for memory, got %q", cfg.Persistence.DataDir)
	}
}

// TestPersistenceLoad_OverlayFromTOML verifies that a persistence section in
// TOML overlays the preset defaults correctly.
func TestPersistenceLoad_OverlayFromTOML(t *testing.T) {
	// Clear ambient env override so the persistence overlay load is deterministic.
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")
	dir := t.TempDir()
	tomlPath := filepath.Join(dir, "config.toml")

	tomlContent := `
mode = "dev"
public_origin = "http://localhost:9200"

[persistence]
backend = "json"
data_dir = "/tmp/ocm-data"
`
	if err := os.WriteFile(tomlPath, []byte(tomlContent), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(LoaderOptions{ConfigPath: tomlPath})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Persistence.Backend != BackendJSON {
		t.Errorf("expected Backend=%q, got %q", BackendJSON, cfg.Persistence.Backend)
	}

	if cfg.Persistence.DataDir != "/tmp/ocm-data" {
		t.Errorf("expected DataDir=/tmp/ocm-data, got %q", cfg.Persistence.DataDir)
	}
}

// TestPersistenceLoad_MirrorOverlay verifies mirror backend config loads without
// a mirror subsection.
func TestPersistenceLoad_MirrorOverlay(t *testing.T) {
	// Clear ambient env override so the mirror overlay load is deterministic.
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")
	dir := t.TempDir()
	tomlPath := filepath.Join(dir, "config.toml")

	tomlContent := `
mode = "dev"
public_origin = "http://localhost:9200"

[persistence]
backend = "mirror"
data_dir = "/tmp/ocm-mirror"
`
	if err := os.WriteFile(tomlPath, []byte(tomlContent), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(LoaderOptions{ConfigPath: tomlPath})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Persistence.Backend != BackendMirror {
		t.Errorf("expected Backend=%q, got %q", BackendMirror, cfg.Persistence.Backend)
	}

	if cfg.Persistence.DataDir != "/tmp/ocm-mirror" {
		t.Errorf("expected DataDir=/tmp/ocm-mirror, got %q", cfg.Persistence.DataDir)
	}
}

// TestPersistenceLoad_UnknownBackendFails verifies that an unknown backend
// value fails validation with a clear error. No silent fallback to memory.
func TestPersistenceLoad_UnknownBackendFails(t *testing.T) {
	// Clear ambient env override so the unknown-backend validation path is deterministic.
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")
	dir := t.TempDir()
	tomlPath := filepath.Join(dir, "config.toml")

	tomlContent := `
mode = "dev"
public_origin = "http://localhost:9200"

[persistence]
backend = "postgres"
data_dir = "/tmp/data"
`
	if err := os.WriteFile(tomlPath, []byte(tomlContent), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: tomlPath})
	if err == nil {
		t.Fatal("expected error for unknown backend, got nil")
	}
}

// TestPersistenceLoad_DataDirRequiredForDurableBackends verifies that json,
// sqlite, and mirror all require data_dir to be set.
func TestPersistenceLoad_DataDirRequiredForDurableBackends(t *testing.T) {
	durableBackends := []string{BackendJSON, BackendSQLite, BackendMirror}

	for _, backend := range durableBackends {
		t.Run(backend, func(t *testing.T) {
			// Clear ambient env override so each durable-backend validation is deterministic.
			t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")
			dir := t.TempDir()
			tomlPath := filepath.Join(dir, "config.toml")

			tomlContent := "mode = \"dev\"\npublic_origin = \"http://localhost:9200\"\n" +
				"\n[persistence]\nbackend = \"" + backend + "\"\n"

			if err := os.WriteFile(tomlPath, []byte(tomlContent), 0600); err != nil {
				t.Fatalf("write config: %v", err)
			}

			_, err := Load(LoaderOptions{ConfigPath: tomlPath})
			if err == nil {
				t.Fatalf("backend=%q: expected error for missing data_dir, got nil", backend)
			}
		})
	}
}

// TestPersistenceLoad_MemoryNoDataDirRequired verifies that the memory
// backend does not require data_dir.
func TestPersistenceLoad_MemoryNoDataDirRequired(t *testing.T) {
	// Clear ambient env override so the memory backend load is deterministic.
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")
	dir := t.TempDir()
	tomlPath := filepath.Join(dir, "config.toml")

	tomlContent := `
mode = "dev"
public_origin = "http://localhost:9200"

[persistence]
backend = "memory"
`
	if err := os.WriteFile(tomlPath, []byte(tomlContent), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(LoaderOptions{ConfigPath: tomlPath})
	if err != nil {
		t.Fatalf("Load() error = %v (memory backend must not require data_dir)", err)
	}

	if cfg.Persistence.Backend != BackendMemory {
		t.Errorf("expected Backend=%q, got %q", BackendMemory, cfg.Persistence.Backend)
	}
}

// TestPersistenceLoad_ExplicitEmptyBackendFails verifies that an explicitly
// empty `backend = ""` in TOML fails with a clear error and is not silently
// treated as an absent key that would fall back to the preset memory value.
func TestPersistenceLoad_ExplicitEmptyBackendFails(t *testing.T) {
	// Clear ambient env override so the empty-backend validation path is deterministic.
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")
	dir := t.TempDir()
	tomlPath := filepath.Join(dir, "config.toml")

	tomlContent := `
mode = "dev"
public_origin = "http://localhost:9200"

[persistence]
backend = ""
`
	if err := os.WriteFile(tomlPath, []byte(tomlContent), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: tomlPath})
	if err == nil {
		t.Fatal("expected error for explicit empty backend, got nil")
	}
}

// TestPersistenceLoad_OverlayPreservesUnchangedFields verifies that a partial
// persistence overlay does not reset unrelated preset fields.
func TestPersistenceLoad_OverlayPreservesUnchangedFields(t *testing.T) {
	// Clear ambient env override so the overlay load is deterministic.
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")
	dir := t.TempDir()
	tomlPath := filepath.Join(dir, "config.toml")

	// Only set data_dir and backend; mirror section is absent.
	tomlContent := `
mode = "dev"
public_origin = "http://localhost:9200"

[persistence]
backend = "json"
data_dir = "/some/path"
`
	if err := os.WriteFile(tomlPath, []byte(tomlContent), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(LoaderOptions{ConfigPath: tomlPath})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Persistence.Backend != BackendJSON {
		t.Errorf("expected Backend=%q, got %q", BackendJSON, cfg.Persistence.Backend)
	}

	if cfg.Persistence.DataDir != "/some/path" {
		t.Errorf("expected DataDir=/some/path, got %q", cfg.Persistence.DataDir)
	}
}
