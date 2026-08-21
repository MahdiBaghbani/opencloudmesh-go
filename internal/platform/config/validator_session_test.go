// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package config

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

func TestLoad_ValidatorSessionSection_OverlaysPreset(t *testing.T) {
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")

	tomlContent := validatorModeTestBaseTOML + `
[http.interceptors.ratelimit.profiles.scan_public.start_public]
requests_per_window = 10
window_seconds = 60

[validator.session]
in_flight_passive_limit = 7
created_ttl_seconds = 11
passive_running_ttl_seconds = 13
passive_complete_ttl_seconds = 17
terminal_retention_days = 19
stall_timeout_seconds = 23
reverse_share_timeout_seconds = 21
`
	configPath := writeTempConfig(t, tomlContent)

	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Validator.Session.InFlightPassiveLimit != 7 {
		t.Errorf("InFlightPassiveLimit = %d, want 7", cfg.Validator.Session.InFlightPassiveLimit)
	}

	if cfg.Validator.Session.CreatedTTLSeconds != 11 {
		t.Errorf("CreatedTTLSeconds = %d, want 11", cfg.Validator.Session.CreatedTTLSeconds)
	}

	if cfg.Validator.Session.PassiveRunningTTLSeconds != 13 {
		t.Errorf("PassiveRunningTTLSeconds = %d, want 13", cfg.Validator.Session.PassiveRunningTTLSeconds)
	}

	if cfg.Validator.Session.PassiveCompleteTTLSeconds != 17 {
		t.Errorf("PassiveCompleteTTLSeconds = %d, want 17", cfg.Validator.Session.PassiveCompleteTTLSeconds)
	}

	if cfg.Validator.Session.TerminalRetentionDays != 19 {
		t.Errorf("TerminalRetentionDays = %d, want 19", cfg.Validator.Session.TerminalRetentionDays)
	}

	if cfg.Validator.Session.StallTimeoutSeconds != 23 {
		t.Errorf("StallTimeoutSeconds = %d, want 23", cfg.Validator.Session.StallTimeoutSeconds)
	}

	if cfg.Validator.Session.ReverseShareTimeoutSeconds != 21 {
		t.Errorf("ReverseShareTimeoutSeconds = %d, want 21", cfg.Validator.Session.ReverseShareTimeoutSeconds)
	}

	got := SessionConfigFromValidator(cfg)

	want := validatorcore.SessionConfig{
		InFlightPassiveLimit:       7,
		CreatedTTLSeconds:          11,
		PassiveRunningTTLSeconds:   13,
		PassiveCompleteTTLSeconds:  17,
		TerminalRetentionDays:      19,
		StallTimeoutSeconds:        23,
		ReverseShareTimeoutSeconds: 21,
	}
	if got != want {
		t.Errorf("SessionConfigFromValidator() = %+v, want %+v", got, want)
	}
}

func TestLoad_ValidatorSessionSection_ReverseShareTimeoutDefaultsToStallWindowBound(t *testing.T) {
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")

	configPath := writeTempConfig(t, validatorModeTestBaseTOML)

	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	got := SessionConfigFromValidator(cfg)

	if got.ReverseShareTimeoutSeconds != 43200 {
		t.Errorf("ReverseShareTimeoutSeconds = %d, want default 43200", got.ReverseShareTimeoutSeconds)
	}

	if got.ReverseShareTimeoutSeconds > got.StallTimeoutSeconds {
		t.Errorf("ReverseShareTimeoutSeconds = %d exceeds StallTimeoutSeconds = %d",
			got.ReverseShareTimeoutSeconds, got.StallTimeoutSeconds)
	}
}

func TestLoad_ValidatorSessionSection_ReverseShareTimeoutExceedingStallWindowFailsBoot(t *testing.T) {
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")

	tomlContent := validatorModeTestBaseTOML + `
[validator.session]
stall_timeout_seconds = 23
reverse_share_timeout_seconds = 24
`
	configPath := writeTempConfig(t, tomlContent)

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("Load() error = nil, want reverse_share_timeout above stall window to fail closed")
	}
}

func TestLoad_ValidatorSessionSection_NonPositiveReverseShareTimeoutReadsAsDefault(t *testing.T) {
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")

	tomlContent := validatorModeTestBaseTOML + `
[validator.session]
reverse_share_timeout_seconds = 0
`
	configPath := writeTempConfig(t, tomlContent)

	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if got := SessionConfigFromValidator(cfg); got.ReverseShareTimeoutSeconds != 43200 {
		t.Errorf("ReverseShareTimeoutSeconds = %d, want default 43200", got.ReverseShareTimeoutSeconds)
	}
}
