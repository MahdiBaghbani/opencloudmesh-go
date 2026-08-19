// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package config

// StatisticsConfig holds federation validator statistics settings under [statistics].
// The shared 32-byte redaction salt is minted at startup into
// persistence.data_dir/redaction.salt (mode 0600); it is not stored in TOML.
type StatisticsConfig struct {
	// Enabled turns on statistics host hashing and related exports.
	Enabled bool `toml:"enabled"`
}

// IsValidatorMode reports whether cfg runs in federation validator mode.
func IsValidatorMode(cfg *Config) bool {
	return cfg != nil && cfg.Mode == string(ModeValidator)
}

// IsTLSModeTerminated reports whether TLS terminates at an upstream reverse proxy.
func IsTLSModeTerminated(cfg *Config) bool {
	return cfg != nil && cfg.TLS.Mode == tlsModeTerminated
}
