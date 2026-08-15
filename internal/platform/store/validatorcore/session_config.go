// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

const (
	defaultInFlightPassiveLimit      = 32
	defaultCreatedTTLSeconds         = 300
	defaultPassiveRunningTTLSeconds  = 900
	defaultPassiveCompleteTTLSeconds = 3600
	defaultTerminalRetentionDays     = 30
)

// SessionConfig holds federation validator session limits and TTL knobs.
type SessionConfig struct {
	InFlightPassiveLimit      int
	CreatedTTLSeconds         int
	PassiveRunningTTLSeconds  int
	PassiveCompleteTTLSeconds int
	TerminalRetentionDays     int
}

// DefaultSessionConfig returns production-safe session defaults.
func DefaultSessionConfig() SessionConfig {
	return SessionConfig{
		InFlightPassiveLimit:      defaultInFlightPassiveLimit,
		CreatedTTLSeconds:         defaultCreatedTTLSeconds,
		PassiveRunningTTLSeconds:  defaultPassiveRunningTTLSeconds,
		PassiveCompleteTTLSeconds: defaultPassiveCompleteTTLSeconds,
		TerminalRetentionDays:     defaultTerminalRetentionDays,
	}
}
