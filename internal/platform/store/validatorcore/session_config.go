// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

const (
	defaultInFlightPassiveLimit       = 32
	defaultCreatedTTLSeconds          = 300
	defaultPassiveRunningTTLSeconds   = 900
	defaultPassiveCompleteTTLSeconds  = 3600
	defaultTerminalRetentionDays      = 30
	defaultStallTimeoutSeconds        = 43200
	defaultReverseShareTimeoutSeconds = 43200
	defaultMaxDriveIdleSeconds        = 1800
	defaultReapIntervalSeconds        = 1
	defaultSessionLimit               = 16
	defaultMaxDispatchAttempts        = 5
	defaultBackoffBaseSeconds         = 1
	defaultBackoffCapSeconds          = 60
)

// SessionConfig holds federation validator session limits and TTL knobs.
type SessionConfig struct {
	InFlightPassiveLimit      int
	CreatedTTLSeconds         int
	PassiveRunningTTLSeconds  int
	PassiveCompleteTTLSeconds int
	TerminalRetentionDays     int

	// StallTimeoutSeconds is the inactivity window for the one active run:
	// an active session whose updated_at is older than this window is
	// interrupted by the stall sweep. Non-positive disables the sweep.
	StallTimeoutSeconds int

	// ReverseShareTimeoutSeconds is the declared reverse-share wait budget.
	// The stall sweep enforces it through the reverse_share_timeout reason,
	// so it must never exceed StallTimeoutSeconds; config load fails closed
	// when it does. Non-positive values fall back to the default.
	ReverseShareTimeoutSeconds int

	// MaxDriveIdleSeconds is the drive idle window. Default 1800; must
	// satisfy 0 < max_drive_idle < stall_timeout_seconds.
	MaxDriveIdleSeconds int

	// ReapIntervalSeconds is the reaper cadence. Default 1; must
	// satisfy reap_interval <= max_drive_idle_seconds.
	ReapIntervalSeconds int

	// SessionLimit is the driving worker cap. Default 16; must satisfy
	// 1 <= session_limit <= 256.
	SessionLimit int

	// MaxDispatchAttempts is the dispatch attempt cap. Default 5; must
	// be > 0.
	MaxDispatchAttempts int

	// BackoffBaseSeconds is the backoff base. Default 1; must be > 0.
	BackoffBaseSeconds int

	// BackoffCapSeconds is the backoff cap. Default 60; must satisfy
	// backoff_cap >= backoff_base_seconds.
	BackoffCapSeconds int
}

// DefaultSessionConfig returns production-safe session defaults.
func DefaultSessionConfig() SessionConfig {
	return SessionConfig{
		InFlightPassiveLimit:       defaultInFlightPassiveLimit,
		CreatedTTLSeconds:          defaultCreatedTTLSeconds,
		PassiveRunningTTLSeconds:   defaultPassiveRunningTTLSeconds,
		PassiveCompleteTTLSeconds:  defaultPassiveCompleteTTLSeconds,
		TerminalRetentionDays:      defaultTerminalRetentionDays,
		StallTimeoutSeconds:        defaultStallTimeoutSeconds,
		ReverseShareTimeoutSeconds: defaultReverseShareTimeoutSeconds,
		MaxDriveIdleSeconds:        defaultMaxDriveIdleSeconds,
		ReapIntervalSeconds:        defaultReapIntervalSeconds,
		SessionLimit:               defaultSessionLimit,
		MaxDispatchAttempts:        defaultMaxDispatchAttempts,
		BackoffBaseSeconds:         defaultBackoffBaseSeconds,
		BackoffCapSeconds:          defaultBackoffCapSeconds,
	}
}
