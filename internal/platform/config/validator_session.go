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
	InFlightPassiveLimit      int `toml:"in_flight_passive_limit"`
	CreatedTTLSeconds         int `toml:"created_ttl_seconds"`
	PassiveRunningTTLSeconds  int `toml:"passive_running_ttl_seconds"`
	PassiveCompleteTTLSeconds int `toml:"passive_complete_ttl_seconds"`
	TerminalRetentionDays     int `toml:"terminal_retention_days"`
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

	return out
}

// ValidatorSection holds federation-validator-specific config knobs.
type ValidatorSection struct {
	Session ValidatorSessionConfig `toml:"session"`
}
