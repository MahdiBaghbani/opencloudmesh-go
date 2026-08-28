// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package config

import (
	"strings"
	"testing"
)

func TestActiveEnabled_NilSemantics(t *testing.T) {
	t.Parallel()

	falseVal := false
	trueVal := true

	tests := []struct {
		name string
		cfg  ValidatorSection
		want bool
	}{
		{name: "unset active section defaults to enabled", cfg: ValidatorSection{}, want: true},
		{name: "nil enabled knob defaults to enabled", cfg: ValidatorSection{Active: ValidatorActiveConfig{}}, want: true},
		{name: "explicit true is enabled", cfg: ValidatorSection{Active: ValidatorActiveConfig{Enabled: &trueVal}}, want: true},
		{name: "explicit false is the opt-out", cfg: ValidatorSection{Active: ValidatorActiveConfig{Enabled: &falseVal}}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := tt.cfg.ActiveEnabled(); got != tt.want {
				t.Errorf("ActiveEnabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidatorConfig_ActiveEnabledDefaultTrue(t *testing.T) {
	t.Parallel()

	if !ValidatorConfig().Validator.ActiveEnabled() {
		t.Error("validator preset must default ActiveEnabled to true")
	}
}

func TestLoad_ValidatorActive_DefaultTrue(t *testing.T) {
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")

	tomlContent := validatorModeTestBaseTOML + `
[http.interceptors.ratelimit.profiles.scan_public.start_public]
requests_per_window = 10
window_seconds = 60
`
	configPath := writeTempConfig(t, tomlContent)

	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if !cfg.Validator.ActiveEnabled() {
		t.Error("ActiveEnabled must default to true when [validator.active] is unset")
	}
}

func TestLoad_ValidatorActive_EmptyActiveTableKeepsDefaultTrue(t *testing.T) {
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")

	tomlContent := validatorModeTestBaseTOML + `
[http.interceptors.ratelimit.profiles.scan_public.start_public]
requests_per_window = 10
window_seconds = 60

[validator.active]
`
	configPath := writeTempConfig(t, tomlContent)

	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if !cfg.Validator.ActiveEnabled() {
		t.Error("empty [validator.active] must keep the default-true Enabled value")
	}
}

func TestLoad_ValidatorActive_ExplicitFalse(t *testing.T) {
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")

	tomlContent := validatorModeTestBaseTOML + `
[http.interceptors.ratelimit.profiles.scan_public.start_public]
requests_per_window = 10
window_seconds = 60

[validator.active]
enabled = false
`
	configPath := writeTempConfig(t, tomlContent)

	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Validator.ActiveEnabled() {
		t.Error("explicit validator.active.enabled = false must disable active legs")
	}
}

func TestLoad_ValidatorActive_ExplicitTrue(t *testing.T) {
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")

	tomlContent := validatorModeTestBaseTOML + `
[http.interceptors.ratelimit.profiles.scan_public.start_public]
requests_per_window = 10
window_seconds = 60

[validator.active]
enabled = true
`
	configPath := writeTempConfig(t, tomlContent)

	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if !cfg.Validator.ActiveEnabled() {
		t.Error("explicit validator.active.enabled = true must keep active legs enabled")
	}
}

func TestLoad_ValidatorMode_RejectsSSRFOff(t *testing.T) {
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")

	tomlContent := validatorModeTestBaseTOML + `
[http.interceptors.ratelimit.profiles.scan_public.start_public]
requests_per_window = 10
window_seconds = 60

[outbound_http.ssrf]
mode = "off"
`
	configPath := writeTempConfig(t, tomlContent)

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected Load to reject outbound_http.ssrf.mode=off in validator mode")
	}

	if !strings.Contains(err.Error(), "mode=validator requires outbound_http.ssrf.mode=strict") {
		t.Fatalf("error = %v, want validator SSRF guard", err)
	}
}

func TestValidateValidatorModeStartupGuardrails_RejectsSSRFOff(t *testing.T) {
	t.Parallel()

	cfg := ValidatorConfig()
	cfg.OutboundHTTP.SSRF.Mode = ssrfModeOff

	err := ValidateValidatorModeStartupGuardrails(cfg)
	if err == nil {
		t.Fatal("expected validator-mode guardrails to reject ssrf.mode=off")
	}

	if !strings.Contains(err.Error(), "mode=validator requires outbound_http.ssrf.mode=strict") {
		t.Fatalf("error = %v, want validator SSRF guard", err)
	}
}

func TestValidateValidatorModeStartupGuardrails_AcceptsPreset(t *testing.T) {
	t.Parallel()

	if err := ValidateValidatorModeStartupGuardrails(ValidatorConfig()); err != nil {
		t.Fatalf("validator preset must satisfy validator-mode guardrails: %v", err)
	}
}

func TestValidateValidatorModeStartupGuardrails_NoopsOutsideValidatorMode(t *testing.T) {
	t.Parallel()

	cfg := DevConfig()
	if err := ValidateValidatorModeStartupGuardrails(cfg); err != nil {
		t.Fatalf("dev mode must not apply the validator SSRF guard: %v", err)
	}
}
