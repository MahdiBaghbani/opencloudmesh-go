// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package config

import (
	"path/filepath"
	"testing"
)

func TestLoad_ValidatorToml_LoadsProbeConfig(t *testing.T) {
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")

	configPath := filepath.Join("..", "..", "..", "configs", "validator.toml")

	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Validator.Probe.Email != DefaultValidatorProbeEmail {
		t.Errorf(
			"Validator.Probe.Email = %q, want %q",
			cfg.Validator.Probe.Email,
			DefaultValidatorProbeEmail,
		)
	}

	if cfg.Validator.Probe.DisplayName != DefaultValidatorProbeDisplayName {
		t.Errorf(
			"Validator.Probe.DisplayName = %q, want %q",
			cfg.Validator.Probe.DisplayName,
			DefaultValidatorProbeDisplayName,
		)
	}
}

func TestLoad_ValidatorProbeSection_OverlaysPreset(t *testing.T) {
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")

	tomlContent := validatorModeTestBaseTOML + `
[http.interceptors.ratelimit.profiles.scan_public.start_public]
requests_per_window = 10
window_seconds = 60

[validator.probe]
email = "scan@validator.example"
display_name = "Scan Probe"
`
	configPath := writeTempConfig(t, tomlContent)

	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Validator.Probe.Email != "scan@validator.example" {
		t.Errorf("Validator.Probe.Email = %q, want scan@validator.example", cfg.Validator.Probe.Email)
	}

	if cfg.Validator.Probe.DisplayName != "Scan Probe" {
		t.Errorf("Validator.Probe.DisplayName = %q, want Scan Probe", cfg.Validator.Probe.DisplayName)
	}
}

func TestValidatorConfig_ProbeDefaults(t *testing.T) {
	t.Parallel()

	cfg := ValidatorConfig()

	if cfg.Validator.Probe.Email != DefaultValidatorProbeEmail {
		t.Errorf(
			"Probe.Email = %q, want %q",
			cfg.Validator.Probe.Email,
			DefaultValidatorProbeEmail,
		)
	}

	if cfg.Validator.Probe.DisplayName != DefaultValidatorProbeDisplayName {
		t.Errorf(
			"Probe.DisplayName = %q, want %q",
			cfg.Validator.Probe.DisplayName,
			DefaultValidatorProbeDisplayName,
		)
	}
}
