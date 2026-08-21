// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package config

import (
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

	return out
}

// ValidatorProbeConfig holds the local probe party fields under [validator.probe].
type ValidatorProbeConfig struct {
	Email       string `toml:"email"`
	DisplayName string `toml:"display_name"`
}

// ValidatorSection holds federation-validator-specific config knobs.
type ValidatorSection struct {
	Session ValidatorSessionConfig `toml:"session"`
	Probe   ValidatorProbeConfig   `toml:"probe"`
}

// validatorFileConfig decodes the optional [validator] TOML table.
type validatorFileConfig struct {
	Session *ValidatorSessionConfig `toml:"session"`
	Probe   *ValidatorProbeConfig   `toml:"probe"`
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
}
