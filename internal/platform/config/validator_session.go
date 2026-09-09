// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package config

import (
	"fmt"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

// ValidatorSessionConfig holds optional session limits under [validator.session].
type ValidatorSessionConfig struct {
	InFlightPassiveLimit       int `toml:"in_flight_passive_limit"`
	CreatedTTLSeconds          int `toml:"created_ttl_seconds"`
	PassiveRunningTTLSeconds   int `toml:"passive_running_ttl_seconds"`
	PassiveCompleteTTLSeconds  int `toml:"passive_complete_ttl_seconds"`
	TerminalRetentionDays      int `toml:"terminal_retention_days"`
	StallTimeoutSeconds        int `toml:"stall_timeout_seconds"`
	ReverseShareTimeoutSeconds int `toml:"reverse_share_timeout_seconds"`
	MaxDriveIdleSeconds        int `toml:"max_drive_idle_seconds"`
	ReapIntervalSeconds        int `toml:"reap_interval_seconds"`
	SessionLimit               int `toml:"session_limit"`
	MaxDispatchAttempts        int `toml:"max_dispatch_attempts"`
	BackoffBaseSeconds         int `toml:"backoff_base_seconds"`
	BackoffCapSeconds          int `toml:"backoff_cap_seconds"`
}

// SessionConfigFromValidator returns validatorcore session limits from cfg.
func SessionConfigFromValidator(cfg *Config) validatorcore.SessionConfig {
	defaults := validatorcore.DefaultSessionConfig()
	if cfg == nil {
		return defaults
	}

	vs := cfg.Validator.Session
	out := defaults

	if vs.InFlightPassiveLimit > 0 {
		out.InFlightPassiveLimit = vs.InFlightPassiveLimit
	}

	if vs.CreatedTTLSeconds > 0 {
		out.CreatedTTLSeconds = vs.CreatedTTLSeconds
	}

	if vs.PassiveRunningTTLSeconds > 0 {
		out.PassiveRunningTTLSeconds = vs.PassiveRunningTTLSeconds
	}

	if vs.PassiveCompleteTTLSeconds > 0 {
		out.PassiveCompleteTTLSeconds = vs.PassiveCompleteTTLSeconds
	}

	if vs.TerminalRetentionDays > 0 {
		out.TerminalRetentionDays = vs.TerminalRetentionDays
	}

	if vs.StallTimeoutSeconds > 0 {
		out.StallTimeoutSeconds = vs.StallTimeoutSeconds
	}

	if vs.ReverseShareTimeoutSeconds > 0 {
		out.ReverseShareTimeoutSeconds = vs.ReverseShareTimeoutSeconds
	}

	if vs.MaxDriveIdleSeconds > 0 {
		out.MaxDriveIdleSeconds = vs.MaxDriveIdleSeconds
	}

	if vs.ReapIntervalSeconds > 0 {
		out.ReapIntervalSeconds = vs.ReapIntervalSeconds
	}

	if vs.SessionLimit > 0 {
		out.SessionLimit = vs.SessionLimit
	}

	if vs.MaxDispatchAttempts > 0 {
		out.MaxDispatchAttempts = vs.MaxDispatchAttempts
	}

	if vs.BackoffBaseSeconds > 0 {
		out.BackoffBaseSeconds = vs.BackoffBaseSeconds
	}

	if vs.BackoffCapSeconds > 0 {
		out.BackoffCapSeconds = vs.BackoffCapSeconds
	}

	return out
}

// ValidatorProbeConfig holds the local probe party fields under [validator.probe].
type ValidatorProbeConfig struct {
	Email       string `toml:"email"`
	DisplayName string `toml:"display_name"`
}

// ValidatorActiveConfig holds the optional [validator.active] knobs.
type ValidatorActiveConfig struct {
	// Enabled turns on active-session legs. Nil means enabled (the default);
	// explicit false is the passive-only opt-out.
	Enabled *bool `toml:"enabled"`
}

// ValidatorSection holds federation-validator-specific config knobs.
type ValidatorSection struct {
	Session ValidatorSessionConfig `toml:"session"`
	Probe   ValidatorProbeConfig   `toml:"probe"`
	Active  ValidatorActiveConfig  `toml:"active"`
}

// ActiveEnabled reports whether active-session legs should be built.
// Unset configuration evaluates to enabled.
func (s ValidatorSection) ActiveEnabled() bool {
	if s.Active.Enabled == nil {
		return true
	}

	return *s.Active.Enabled
}

// validatorActiveFileConfig decodes the optional [validator.active] table.
type validatorActiveFileConfig struct {
	Enabled *bool `toml:"enabled"`
}

// validatorFileConfig decodes the optional [validator] TOML table.
type validatorFileConfig struct {
	Session *ValidatorSessionConfig    `toml:"session"`
	Probe   *ValidatorProbeConfig      `toml:"probe"`
	Active  *validatorActiveFileConfig `toml:"active"`
}

func overlayValidatorConfig(cfg *Config, fc *validatorFileConfig) {
	if fc == nil {
		return
	}

	if fc.Session != nil {
		overlayValidatorSessionConfig(cfg, fc.Session)
	}

	if fc.Probe != nil {
		if fc.Probe.Email != "" {
			cfg.Validator.Probe.Email = fc.Probe.Email
		}

		if fc.Probe.DisplayName != "" {
			cfg.Validator.Probe.DisplayName = fc.Probe.DisplayName
		}
	}

	overlayValidatorActiveConfig(cfg, fc.Active)
}

func overlayValidatorActiveConfig(cfg *Config, active *validatorActiveFileConfig) {
	if active == nil || active.Enabled == nil {
		return
	}

	cfg.Validator.Active.Enabled = active.Enabled
}

func overlayValidatorSessionConfig(cfg *Config, session *ValidatorSessionConfig) {
	if session.InFlightPassiveLimit > 0 {
		cfg.Validator.Session.InFlightPassiveLimit = session.InFlightPassiveLimit
	}

	if session.CreatedTTLSeconds > 0 {
		cfg.Validator.Session.CreatedTTLSeconds = session.CreatedTTLSeconds
	}

	if session.PassiveRunningTTLSeconds > 0 {
		cfg.Validator.Session.PassiveRunningTTLSeconds = session.PassiveRunningTTLSeconds
	}

	if session.PassiveCompleteTTLSeconds > 0 {
		cfg.Validator.Session.PassiveCompleteTTLSeconds = session.PassiveCompleteTTLSeconds
	}

	if session.TerminalRetentionDays > 0 {
		cfg.Validator.Session.TerminalRetentionDays = session.TerminalRetentionDays
	}

	if session.StallTimeoutSeconds > 0 {
		cfg.Validator.Session.StallTimeoutSeconds = session.StallTimeoutSeconds
	}

	if session.ReverseShareTimeoutSeconds > 0 {
		cfg.Validator.Session.ReverseShareTimeoutSeconds = session.ReverseShareTimeoutSeconds
	}

	if session.MaxDriveIdleSeconds > 0 {
		cfg.Validator.Session.MaxDriveIdleSeconds = session.MaxDriveIdleSeconds
	}

	if session.ReapIntervalSeconds > 0 {
		cfg.Validator.Session.ReapIntervalSeconds = session.ReapIntervalSeconds
	}

	if session.SessionLimit > 0 {
		cfg.Validator.Session.SessionLimit = session.SessionLimit
	}

	if session.MaxDispatchAttempts > 0 {
		cfg.Validator.Session.MaxDispatchAttempts = session.MaxDispatchAttempts
	}

	if session.BackoffBaseSeconds > 0 {
		cfg.Validator.Session.BackoffBaseSeconds = session.BackoffBaseSeconds
	}

	if session.BackoffCapSeconds > 0 {
		cfg.Validator.Session.BackoffCapSeconds = session.BackoffCapSeconds
	}
}

// rejectNegativeValidatorSessionConcurrency fails closed on raw negative
// values for the six concurrency knobs. Zero means absent/default and is
// left for overlay. Old session knobs keep their existing >0 overlay
// semantics and are not checked here.
func rejectNegativeValidatorSessionConcurrency(session *ValidatorSessionConfig) error {
	if session == nil {
		return nil
	}

	if session.MaxDriveIdleSeconds < 0 {
		return fmt.Errorf(
			"validator.session.max_drive_idle_seconds (%d) must not be negative",
			session.MaxDriveIdleSeconds,
		)
	}

	if session.ReapIntervalSeconds < 0 {
		return fmt.Errorf(
			"validator.session.reap_interval_seconds (%d) must not be negative",
			session.ReapIntervalSeconds,
		)
	}

	if session.SessionLimit < 0 {
		return fmt.Errorf(
			"validator.session.session_limit (%d) must not be negative",
			session.SessionLimit,
		)
	}

	if session.MaxDispatchAttempts < 0 {
		return fmt.Errorf(
			"validator.session.max_dispatch_attempts (%d) must not be negative",
			session.MaxDispatchAttempts,
		)
	}

	if session.BackoffBaseSeconds < 0 {
		return fmt.Errorf(
			"validator.session.backoff_base_seconds (%d) must not be negative",
			session.BackoffBaseSeconds,
		)
	}

	if session.BackoffCapSeconds < 0 {
		return fmt.Errorf(
			"validator.session.backoff_cap_seconds (%d) must not be negative",
			session.BackoffCapSeconds,
		)
	}

	return nil
}
