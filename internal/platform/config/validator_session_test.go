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
max_drive_idle_seconds = 5
reverse_share_timeout_seconds = 21
`
	configPath := writeTempConfig(t, tomlContent)

	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	assertOverlaysPresetRawFields(t, cfg.Validator.Session)

	got := SessionConfigFromValidator(cfg)
	assertResolvedConcurrencyKnobs(t, got, resolvedConcurrencyKnobs{
		MaxDriveIdleSeconds: 5,
		ReapIntervalSeconds: 1,
		SessionLimit:        16,
		MaxDispatchAttempts: 5,
		BackoffBaseSeconds:  1,
		BackoffCapSeconds:   60,
	})

	want := validatorcore.SessionConfig{
		InFlightPassiveLimit:       7,
		CreatedTTLSeconds:          11,
		PassiveRunningTTLSeconds:   13,
		PassiveCompleteTTLSeconds:  17,
		TerminalRetentionDays:      19,
		StallTimeoutSeconds:        23,
		ReverseShareTimeoutSeconds: 21,
		MaxDriveIdleSeconds:        5,
		ReapIntervalSeconds:        1,
		SessionLimit:               16,
		MaxDispatchAttempts:        5,
		BackoffBaseSeconds:         1,
		BackoffCapSeconds:          60,
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
max_drive_idle_seconds = 5
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

func TestLoad_ValidatorSessionSection_ConcurrencyKnobsAbsentResolveDefaults(t *testing.T) {
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")

	cfg, err := Load(LoaderOptions{ConfigPath: writeTempConfig(t, validatorModeTestBaseTOML)})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	assertResolvedConcurrencyKnobs(t, SessionConfigFromValidator(cfg), defaultResolvedConcurrencyKnobs())
}

func TestLoad_ValidatorSessionSection_ConcurrencyKnobsZeroResolveDefaults(t *testing.T) {
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")

	tomlContent := validatorModeTestBaseTOML + `
[validator.session]
max_drive_idle_seconds = 0
reap_interval_seconds = 0
session_limit = 0
max_dispatch_attempts = 0
backoff_base_seconds = 0
backoff_cap_seconds = 0
`

	cfg, err := Load(LoaderOptions{ConfigPath: writeTempConfig(t, tomlContent)})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	assertResolvedConcurrencyKnobs(t, SessionConfigFromValidator(cfg), defaultResolvedConcurrencyKnobs())
}

func TestLoad_ValidatorSessionSection_ConcurrencyKnobsNegativeRejected(t *testing.T) {
	for _, key := range []string{
		"max_drive_idle_seconds",
		"reap_interval_seconds",
		"session_limit",
		"max_dispatch_attempts",
		"backoff_base_seconds",
		"backoff_cap_seconds",
	} {
		t.Run(key, func(t *testing.T) {
			t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")

			tomlContent := validatorModeTestBaseTOML + `
[validator.session]
` + key + ` = -1
`

			_, err := Load(LoaderOptions{ConfigPath: writeTempConfig(t, tomlContent)})
			if err == nil {
				t.Fatalf("Load() error = nil, want raw-negative %s to fail closed", key)
			}
		})
	}
}

func TestLoad_ValidatorSessionSection_ConcurrencyPairInvariantsFailBoot(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "reap_interval exceeds max_drive_idle",
			body: `
stall_timeout_seconds = 7200
reverse_share_timeout_seconds = 7200
max_drive_idle_seconds = 5
reap_interval_seconds = 10
`,
		},
		{
			name: "max_drive_idle not less than stall",
			body: `
stall_timeout_seconds = 23
max_drive_idle_seconds = 23
reverse_share_timeout_seconds = 23
`,
		},
		{
			name: "backoff_cap below backoff_base",
			body: `
stall_timeout_seconds = 7200
reverse_share_timeout_seconds = 7200
max_drive_idle_seconds = 10
backoff_base_seconds = 5
backoff_cap_seconds = 3
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")

			tomlContent := validatorModeTestBaseTOML + `
[validator.session]
` + tt.body

			_, err := Load(LoaderOptions{ConfigPath: writeTempConfig(t, tomlContent)})
			if err == nil {
				t.Fatalf("Load() error = nil, want pair invariant %q to fail closed", tt.name)
			}
		})
	}
}

func TestLoad_ValidatorSessionSection_SessionLimitRange(t *testing.T) {
	tests := []struct {
		name      string
		limitLine string
		wantLimit int
		wantErr   bool
	}{
		{name: "session_limit 1", limitLine: "session_limit = 1", wantLimit: 1},
		{name: "session_limit 256", limitLine: "session_limit = 256", wantLimit: 256},
		{name: "session_limit 257", limitLine: "session_limit = 257", wantErr: true},
		{name: "session_limit 0 defaults to 16", limitLine: "session_limit = 0", wantLimit: 16},
		{name: "session_limit -1", limitLine: "session_limit = -1", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")

			tomlContent := validatorModeTestBaseTOML + `
[validator.session]
stall_timeout_seconds = 7200
reverse_share_timeout_seconds = 7200
max_drive_idle_seconds = 10
` + tt.limitLine + `
`

			cfg, err := Load(LoaderOptions{ConfigPath: writeTempConfig(t, tomlContent)})
			if tt.wantErr {
				if err == nil {
					t.Fatal("Load() error = nil, want session_limit range rejection")
				}

				return
			}

			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}

			got := SessionConfigFromValidator(cfg)
			if got.SessionLimit != tt.wantLimit {
				t.Errorf("SessionLimit = %d, want %d", got.SessionLimit, tt.wantLimit)
			}
		})
	}
}

func TestLoad_ValidatorSessionSection_ConcurrencyKnobsAllDefaultNonzero(t *testing.T) {
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")

	tomlContent := validatorModeTestBaseTOML + `
[validator.session]
stall_timeout_seconds = 43200
max_drive_idle_seconds = 100
reap_interval_seconds = 10
session_limit = 8
max_dispatch_attempts = 3
backoff_base_seconds = 2
backoff_cap_seconds = 20
`

	cfg, err := Load(LoaderOptions{ConfigPath: writeTempConfig(t, tomlContent)})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	assertResolvedConcurrencyKnobs(t, SessionConfigFromValidator(cfg), resolvedConcurrencyKnobs{
		MaxDriveIdleSeconds: 100,
		ReapIntervalSeconds: 10,
		SessionLimit:        8,
		MaxDispatchAttempts: 3,
		BackoffBaseSeconds:  2,
		BackoffCapSeconds:   20,
	})
}

func TestLoad_ValidatorSessionSection_ResolvedIdleDefaultExceedingStallFailsBoot(t *testing.T) {
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")

	tomlContent := validatorModeTestBaseTOML + `
[validator.session]
stall_timeout_seconds = 23
reverse_share_timeout_seconds = 23
`

	_, err := Load(LoaderOptions{ConfigPath: writeTempConfig(t, tomlContent)})
	if err == nil {
		t.Fatal("Load() error = nil, want resolved idle default 1800 against stall 23 to fail closed")
	}
}

func assertOverlaysPresetRawFields(t *testing.T, session ValidatorSessionConfig) {
	t.Helper()

	checks := []struct {
		name string
		got  int
		want int
		note string
	}{
		{name: "InFlightPassiveLimit", got: session.InFlightPassiveLimit, want: 7},
		{name: "CreatedTTLSeconds", got: session.CreatedTTLSeconds, want: 11},
		{name: "PassiveRunningTTLSeconds", got: session.PassiveRunningTTLSeconds, want: 13},
		{name: "PassiveCompleteTTLSeconds", got: session.PassiveCompleteTTLSeconds, want: 17},
		{name: "TerminalRetentionDays", got: session.TerminalRetentionDays, want: 19},
		{name: "StallTimeoutSeconds", got: session.StallTimeoutSeconds, want: 23},
		{name: "ReverseShareTimeoutSeconds", got: session.ReverseShareTimeoutSeconds, want: 21},
		{name: "MaxDriveIdleSeconds", got: session.MaxDriveIdleSeconds, want: 5},
		{name: "ReapIntervalSeconds", got: session.ReapIntervalSeconds, want: 0, note: " (absent)"},
		{name: "SessionLimit", got: session.SessionLimit, want: 0, note: " (absent)"},
		{name: "MaxDispatchAttempts", got: session.MaxDispatchAttempts, want: 0, note: " (absent)"},
		{name: "BackoffBaseSeconds", got: session.BackoffBaseSeconds, want: 0, note: " (absent)"},
		{name: "BackoffCapSeconds", got: session.BackoffCapSeconds, want: 0, note: " (absent)"},
	}

	for _, check := range checks {
		if check.got != check.want {
			t.Errorf("%s = %d, want %d%s", check.name, check.got, check.want, check.note)
		}
	}
}

type resolvedConcurrencyKnobs struct {
	MaxDriveIdleSeconds int
	ReapIntervalSeconds int
	SessionLimit        int
	MaxDispatchAttempts int
	BackoffBaseSeconds  int
	BackoffCapSeconds   int
}

func defaultResolvedConcurrencyKnobs() resolvedConcurrencyKnobs {
	return resolvedConcurrencyKnobs{
		MaxDriveIdleSeconds: 1800,
		ReapIntervalSeconds: 1,
		SessionLimit:        16,
		MaxDispatchAttempts: 5,
		BackoffBaseSeconds:  1,
		BackoffCapSeconds:   60,
	}
}

func assertResolvedConcurrencyKnobs(t *testing.T, got validatorcore.SessionConfig, want resolvedConcurrencyKnobs) {
	t.Helper()

	if got.MaxDriveIdleSeconds != want.MaxDriveIdleSeconds {
		t.Errorf("MaxDriveIdleSeconds = %d, want %d", got.MaxDriveIdleSeconds, want.MaxDriveIdleSeconds)
	}

	if got.ReapIntervalSeconds != want.ReapIntervalSeconds {
		t.Errorf("ReapIntervalSeconds = %d, want %d", got.ReapIntervalSeconds, want.ReapIntervalSeconds)
	}

	if got.SessionLimit != want.SessionLimit {
		t.Errorf("SessionLimit = %d, want %d", got.SessionLimit, want.SessionLimit)
	}

	if got.MaxDispatchAttempts != want.MaxDispatchAttempts {
		t.Errorf("MaxDispatchAttempts = %d, want %d", got.MaxDispatchAttempts, want.MaxDispatchAttempts)
	}

	if got.BackoffBaseSeconds != want.BackoffBaseSeconds {
		t.Errorf("BackoffBaseSeconds = %d, want %d", got.BackoffBaseSeconds, want.BackoffBaseSeconds)
	}

	if got.BackoffCapSeconds != want.BackoffCapSeconds {
		t.Errorf("BackoffCapSeconds = %d, want %d", got.BackoffCapSeconds, want.BackoffCapSeconds)
	}
}
