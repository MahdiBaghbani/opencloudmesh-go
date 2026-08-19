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

func TestLoad_TerminatedTLSMode_AcceptedWithTrustedProxies(t *testing.T) {
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
mode = "dev"
public_origin = "https://cloud.example.com"

[tls]
mode = "terminated"

[server]
trusted_proxies = ["127.0.0.0/8", "10.0.0.0/8"]
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.TLS.Mode != tlsModeTerminated {
		t.Errorf("TLS.Mode = %q, want %q", cfg.TLS.Mode, tlsModeTerminated)
	}
}

func TestValidateTerminatedTLSMode_RejectsMissingTrustedProxies(t *testing.T) {
	t.Parallel()

	cfg := &Config{
		TLS:    TLSConfig{Mode: tlsModeTerminated},
		Server: ServerConfig{TrustedProxies: nil},
	}

	err := validateTerminatedTLSMode(cfg)
	if err == nil {
		t.Fatal("expected error when trusted_proxies missing for terminated mode")
	}

	if !strings.Contains(err.Error(), "trusted_proxies") {
		t.Errorf("error = %v, want trusted_proxies validation", err)
	}
}

func TestLoad_TerminatedTLSMode_RejectsOmittedTrustedProxies(t *testing.T) {
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
mode = "dev"
public_origin = "https://cloud.example.com"

[tls]
mode = "terminated"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error when server.trusted_proxies omitted for terminated mode")
	}

	if !strings.Contains(err.Error(), "trusted_proxies") {
		t.Errorf("error = %v, want trusted_proxies validation", err)
	}
}

func TestLoad_TerminatedTLSMode_RejectsMalformedTrustedProxies(t *testing.T) {
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
mode = "dev"
public_origin = "https://cloud.example.com"

[tls]
mode = "terminated"

[server]
trusted_proxies = ["not-a-cidr"]
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error for malformed trusted_proxies in terminated mode")
	}

	if !strings.Contains(err.Error(), "trusted_proxies") {
		t.Errorf("error = %v, want trusted_proxies validation", err)
	}
}

func TestLoad_InvalidTLSMode_ListsTerminated(t *testing.T) {
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
[tls]
mode = "letsencrypt"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error for invalid tls.mode")
	}

	if !strings.Contains(err.Error(), "terminated") {
		t.Errorf("error = %v, want terminated in allowed values", err)
	}
}
