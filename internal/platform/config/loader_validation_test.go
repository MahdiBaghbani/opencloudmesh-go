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

func TestLoad_UnknownKeys_Fail(t *testing.T) {
	// Clear ambient env override so the unknown-keys validation path is deterministic.
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
mode = "dev"

[identity]
session_ttl_hours = 24

[fake_phantom_section]
some_future_key = true

[unknown_section]
random_key = "value"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("Load() should fail with unsupported keys")
	}

	if !strings.Contains(err.Error(), "unsupported keys") {
		t.Errorf("expected unsupported-keys error, got: %v", err)
	}
}

func TestLoad_InvalidTLSMode_FailsFast(t *testing.T) {
	// Clear ambient env override so the TLS mode validation path is deterministic.
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
[tls]
mode = "letsencrypt"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error for invalid tls.mode")
	}

	if !strings.Contains(err.Error(), "invalid tls.mode") {
		t.Errorf("expected tls.mode error, got: %v", err)
	}
}

func TestLoad_InvalidExternalBasePath_FailsFast(t *testing.T) {
	// Clear ambient env override so the base-path validation path is deterministic.
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
mode = "dev"
public_origin = "https://example.com"
external_base_path = "ocm"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error for invalid external_base_path")
	}

	if !strings.Contains(err.Error(), "external_base_path") {
		t.Errorf("expected external_base_path error, got: %v", err)
	}
}

func TestLoad_ValidEnumValues_Succeeds(t *testing.T) {
	// Clear ambient env override so the enum load is deterministic.
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
mode = "dev"

[tls]
mode = "acme"

[outbound_http.ssrf]
mode = "off"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.TLS.Mode != "acme" {
		t.Errorf("expected tls.mode acme, got %s", cfg.TLS.Mode)
	}

	if cfg.OutboundHTTP.SSRF.Mode != "off" {
		t.Errorf("expected ssrf.mode off, got %s", cfg.OutboundHTTP.SSRF.Mode)
	}
}
