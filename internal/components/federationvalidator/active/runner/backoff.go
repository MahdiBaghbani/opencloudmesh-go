// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package runner

import (
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

const maxBackoffShift = 30

// sessionBackoff is per-handle retry delay. Kick resets it so a wake is
// not held behind a stale failure window.
type sessionBackoff struct {
	attempt int
	nextAt  time.Time
}

func (b *sessionBackoff) reset() {
	if b == nil {
		return
	}

	b.attempt = 0
	b.nextAt = time.Time{}
}

func (b *sessionBackoff) recordFailure(cfg validatorcore.SessionConfig, now time.Time) {
	if b == nil {
		return
	}

	if b.attempt < maxBackoffShift {
		b.attempt++
	}

	b.nextAt = now.Add(backoffDelay(b.attempt, cfg.BackoffBaseSeconds, cfg.BackoffCapSeconds))
}

func (b *sessionBackoff) waitDuration(now time.Time) time.Duration {
	if b == nil || b.nextAt.IsZero() || !now.Before(b.nextAt) {
		return 0
	}

	return b.nextAt.Sub(now)
}

func (h *sessionHandle) resetBackoff() {
	if h == nil {
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	h.backoff.reset()
}

func (h *sessionHandle) recordBackoffFailure(cfg validatorcore.SessionConfig, now time.Time) {
	if h == nil {
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	h.backoff.recordFailure(cfg, now)
}

func (h *sessionHandle) backoffWait(now time.Time) time.Duration {
	if h == nil {
		return 0
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	return h.backoff.waitDuration(now)
}

func (r *Runner) sessionConfig() validatorcore.SessionConfig {
	if r == nil {
		return validatorcore.DefaultSessionConfig()
	}

	return r.session
}

func resolveSessionKnobs(deps Deps) validatorcore.SessionConfig {
	defaults := validatorcore.DefaultSessionConfig()
	out := validatorcore.SessionConfig{
		MaxDriveIdleSeconds: deps.MaxDriveIdleSeconds,
		ReapIntervalSeconds: deps.ReapIntervalSeconds,
		SessionLimit:        deps.SessionLimit,
		MaxDispatchAttempts: deps.MaxDispatchAttempts,
		BackoffBaseSeconds:  deps.BackoffBaseSeconds,
		BackoffCapSeconds:   deps.BackoffCapSeconds,
	}

	if out.MaxDriveIdleSeconds <= 0 {
		out.MaxDriveIdleSeconds = defaults.MaxDriveIdleSeconds
	}

	if out.ReapIntervalSeconds <= 0 {
		out.ReapIntervalSeconds = defaults.ReapIntervalSeconds
	}

	if out.SessionLimit <= 0 {
		out.SessionLimit = defaults.SessionLimit
	}

	if out.MaxDispatchAttempts <= 0 {
		out.MaxDispatchAttempts = defaults.MaxDispatchAttempts
	}

	if out.BackoffBaseSeconds <= 0 {
		out.BackoffBaseSeconds = defaults.BackoffBaseSeconds
	}

	if out.BackoffCapSeconds < out.BackoffBaseSeconds {
		out.BackoffCapSeconds = defaults.BackoffCapSeconds
	}

	if out.BackoffCapSeconds < out.BackoffBaseSeconds {
		out.BackoffCapSeconds = out.BackoffBaseSeconds
	}

	return out
}

func driveWorkerCap(limit int) int {
	if limit <= 0 {
		return defaultDriveWorkers
	}

	return limit
}

func backoffDelay(attempt, baseSec, capSec int) time.Duration {
	if attempt <= 0 {
		return 0
	}

	if baseSec <= 0 {
		baseSec = 1
	}

	if capSec < baseSec {
		capSec = baseSec
	}

	shift := min(attempt-1, maxBackoffShift)

	delay := time.Duration(baseSec) * time.Second << shift
	delayCap := time.Duration(capSec) * time.Second

	if delay <= 0 || delay > delayCap {
		return delayCap
	}

	return delay
}
