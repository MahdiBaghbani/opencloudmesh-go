// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package reverseshare_test

import (
	"errors"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

// failingStatsHostHasher injects terminal-stats write failures.
type failingStatsHostHasher struct{}

func (failingStatsHostHasher) HashHost(string) (string, error) {
	return "", errors.New("injected host hash failure")
}

func (failingStatsHostHasher) HashStatsK(string) (string, error) {
	return "", errors.New("injected stats key failure")
}

func TestObserveCreatedShare_EarlySharePassesThroughTimelyPath(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	bobID := env.seedRun(t, "run-observe-early", validatorcore.StateReverseAwaitingShare)
	share := env.addShare(t, bobID, "provider-early", testTargetHost)

	if err := env.svc.ObserveCreatedShare(t.Context(), share); err != nil {
		t.Fatalf("ObserveCreatedShare: %v", err)
	}

	run := env.requireRun(t, "run-observe-early")

	if run.State != validatorcore.StateTerminalPass {
		t.Fatalf("state = %q, want %q", run.State, validatorcore.StateTerminalPass)
	}

	if run.TerminalReason == nil || *run.TerminalReason != "reverse_share_observed" {
		t.Fatalf("terminal_reason = %v, want %q", run.TerminalReason, "reverse_share_observed")
	}

	if run.ReverseShareProviderID == nil || *run.ReverseShareProviderID != "provider-early" {
		t.Fatalf("reverse_share_provider_id = %v, want %q", run.ReverseShareProviderID, "provider-early")
	}

	if run.StatsWrittenAt == nil {
		t.Fatal("stats_written_at = nil, want terminal statistics landed before success")
	}

	if count := env.countStatsRaw(t); count != 1 {
		t.Fatalf("stats_raw count = %d, want 1", count)
	}

	var raw validatorcore.StatsRaw
	if err := env.store.DB().WithContext(t.Context()).First(&raw).Error; err != nil {
		t.Fatalf("load stats_raw: %v", err)
	}

	if raw.GradeSharing == nil || *raw.GradeSharing != validatorcore.GradePass {
		t.Fatalf("grade_sharing = %v, want %q from the share evidence", raw.GradeSharing, validatorcore.GradePass)
	}
}

func TestObserveCreatedShare_LateShareFlipsAfterTimeout(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	ctx := t.Context()

	bobID := env.seedRun(t, "run-observe-late", validatorcore.StateReverseAwaitingShare)

	// Same-boot interruption: the stall sweep terminalizes the wait with the
	// reverse-share timeout reason before the share arrives.
	reason := validatorcore.ReasonReverseShareTimeout
	finished := time.Now().Unix()

	if err := env.store.DB().WithContext(ctx).Model(&validatorcore.TestRun{}).
		Where("test_run_id = ?", "run-observe-late").
		Updates(map[string]any{
			"is_active":       false,
			"state":           validatorcore.StateInterrupted,
			"terminal_reason": reason,
			"finished_at":     finished,
		}).Error; err != nil {
		t.Fatalf("interrupt run: %v", err)
	}

	share := env.addShare(t, bobID, "provider-late", testTargetHost)

	if err := env.svc.ObserveCreatedShare(ctx, share); err != nil {
		t.Fatalf("ObserveCreatedShare: %v", err)
	}

	run := env.requireRun(t, "run-observe-late")

	if run.State != validatorcore.StateTerminalPass {
		t.Fatalf("state = %q, want %q", run.State, validatorcore.StateTerminalPass)
	}

	if run.TerminalReason == nil || *run.TerminalReason != validatorcore.ReasonLateReverseShare {
		t.Fatalf("terminal_reason = %v, want %q", run.TerminalReason, validatorcore.ReasonLateReverseShare)
	}

	if run.FinishedAt == nil || *run.FinishedAt != finished {
		t.Fatalf("finished_at = %v, want preserved %d", run.FinishedAt, finished)
	}

	if run.ReverseShareProviderID == nil || *run.ReverseShareProviderID != "provider-late" {
		t.Fatalf("reverse_share_provider_id = %v, want %q", run.ReverseShareProviderID, "provider-late")
	}

	if count := env.countStatsRaw(t); count != 1 {
		t.Fatalf("stats_raw count = %d, want 1", count)
	}

	// The idempotent duplicate delivery of the same share re-enters the
	// observer: already terminal_pass, so only the stats upsert re-runs.
	if err := env.svc.ObserveCreatedShare(ctx, share); err != nil {
		t.Fatalf("duplicate ObserveCreatedShare: %v", err)
	}

	if count := env.countStatsRaw(t); count != 1 {
		t.Fatalf("stats_raw count after duplicate = %d, want 1 (no double count)", count)
	}
}

func TestObserveCreatedShare_AliceAddressedShareNeverTouchesRun(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	env.seedRun(t, "run-observe-alice", validatorcore.StateReverseAwaitingShare)

	// A share addressed to someone other than Bob persists normally but must
	// not terminalize, stamp occupancy, or flip the run.
	share := env.addShare(t, "alice-local-user", "provider-alice", testTargetHost)

	if err := env.svc.ObserveCreatedShare(t.Context(), share); err != nil {
		t.Fatalf("ObserveCreatedShare: %v", err)
	}

	run := env.requireRun(t, "run-observe-alice")

	if run.State != validatorcore.StateReverseAwaitingShare {
		t.Fatalf("state = %q, want unchanged %q", run.State, validatorcore.StateReverseAwaitingShare)
	}

	if run.ReverseShareProviderID != nil {
		t.Fatalf("reverse_share_provider_id = %v, want nil", run.ReverseShareProviderID)
	}
}

func TestObserveCreatedShare_ShareFromOtherSenderNeverTouchesRun(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	bobID := env.seedRun(t, "run-observe-other-sender", validatorcore.StateReverseAwaitingShare)

	share := env.addShare(t, bobID, "provider-other", "other.example")

	if err := env.svc.ObserveCreatedShare(t.Context(), share); err != nil {
		t.Fatalf("ObserveCreatedShare: %v", err)
	}

	run := env.requireRun(t, "run-observe-other-sender")

	if run.State != validatorcore.StateReverseAwaitingShare {
		t.Fatalf("state = %q, want unchanged %q", run.State, validatorcore.StateReverseAwaitingShare)
	}
}

func TestObserveCreatedShare_StatsFailureSuppressesSuccessAndDuplicateHeals(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	env.store.SetStatsHostHasher(failingStatsHostHasher{})

	bobID := env.seedRun(t, "run-observe-stats-fail", validatorcore.StateReverseAwaitingShare)
	share := env.addShare(t, bobID, "provider-retry", testTargetHost)

	// The state transition commits first; the stats failure surfaces as the
	// observer error so the handler withholds the 201.
	err := env.svc.ObserveCreatedShare(t.Context(), share)
	if err == nil {
		t.Fatal("ObserveCreatedShare error = nil, want the stats failure to surface")
	}

	run := env.requireRun(t, "run-observe-stats-fail")

	if run.State != validatorcore.StateTerminalPass {
		t.Fatalf("state = %q, want %q even with stats down", run.State, validatorcore.StateTerminalPass)
	}

	if run.StatsWrittenAt != nil {
		t.Fatalf("stats_written_at = %v, want nil while stats are failing", run.StatsWrittenAt)
	}

	if run.ReverseShareProviderID != nil {
		t.Fatalf("reverse_share_provider_id = %v, want nil before stats succeed", run.ReverseShareProviderID)
	}

	// The client's retry takes the idempotent-duplicate path, which re-enters
	// the same observer and heals through the keyed stats upsert.
	env.store.SetStatsHostHasher(testStatsHostHasher(t))

	if err := env.svc.ObserveCreatedShare(t.Context(), share); err != nil {
		t.Fatalf("retry ObserveCreatedShare: %v", err)
	}

	healed := env.requireRun(t, "run-observe-stats-fail")

	if healed.StatsWrittenAt == nil {
		t.Fatal("stats_written_at = nil after duplicate retry, want healed")
	}

	if healed.ReverseShareProviderID == nil || *healed.ReverseShareProviderID != "provider-retry" {
		t.Fatalf("reverse_share_provider_id = %v, want %q after heal",
			healed.ReverseShareProviderID, "provider-retry")
	}

	if count := env.countStatsRaw(t); count != 1 {
		t.Fatalf("stats_raw count = %d, want 1 (no double count)", count)
	}
}
