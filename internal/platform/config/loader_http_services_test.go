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

func TestLoad_HTTPServices_FromTOML(t *testing.T) {
	// Clear ambient env override so the HTTP services load is deterministic.
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
mode = "strict"

[http.services.wellknown]
[http.services.wellknown.ocmprovider]
provider = "CustomProvider"

[http.services.ocm]
[http.services.ocm.token_exchange]
path = "auth/token"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if len(cfg.HTTP.Services) != 2 {
		t.Errorf("expected 2 services, got %d", len(cfg.HTTP.Services))
	}

	wellknown, ok := cfg.HTTP.Services["wellknown"]
	if !ok {
		t.Fatal("expected wellknown service in config")
	}

	ocmProvider, ok := wellknown["ocmprovider"].(map[string]any)
	if !ok {
		t.Fatal("expected ocmprovider in wellknown config")
	}

	if ocmProvider["provider"] != "CustomProvider" {
		t.Errorf("expected provider 'CustomProvider', got %v", ocmProvider["provider"])
	}

	ocm, ok := cfg.HTTP.Services["ocm"]
	if !ok {
		t.Fatal("expected ocm service in config")
	}

	tokenExchange, ok := ocm["token_exchange"].(map[string]any)
	if !ok {
		t.Fatal("expected token_exchange in ocm config")
	}

	if tokenExchange["path"] != "auth/token" {
		t.Errorf("expected path 'auth/token', got %v", tokenExchange["path"])
	}
}

func TestBuildServiceConfig_ReturnsNilForUnconfiguredService(t *testing.T) {
	t.Parallel()

	cfg := StrictConfig()

	result := cfg.BuildServiceConfig("nonexistent")
	if result != nil {
		t.Errorf("expected nil for unconfigured service, got %v", result)
	}
}

func TestBuildServiceConfig_ReturnsCopyForConfiguredService(t *testing.T) {
	t.Parallel()

	cfg := StrictConfig()
	cfg.HTTP.Services = map[string]map[string]any{
		"testservice": {
			"key1": "value1",
			"key2": 42,
		},
	}

	result := cfg.BuildServiceConfig("testservice")
	if result == nil {
		t.Fatal("expected non-nil result for configured service")
	}

	if result["key1"] != "value1" {
		t.Errorf("expected key1='value1', got %v", result["key1"])
	}

	if result["key2"] != 42 {
		t.Errorf("expected key2=42, got %v", result["key2"])
	}

	// Verify it's a copy (mutation doesn't affect original)
	result["key1"] = "modified"

	if cfg.HTTP.Services["testservice"]["key1"] != "value1" {
		t.Error("BuildServiceConfig should return a copy, not the original map")
	}
}

func TestHTTPConfig_EmptyServicesDoesNotBreakLoading(t *testing.T) {
	// Clear ambient env override so the default load is deterministic.
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")

	cfg, err := Load(LoaderOptions{})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// HTTP.Services should be nil or empty by default
	if len(cfg.HTTP.Services) > 0 {
		t.Errorf("expected empty HTTP.Services by default, got %d services", len(cfg.HTTP.Services))
	}
}
