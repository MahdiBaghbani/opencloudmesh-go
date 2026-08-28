// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"context"
	"testing"
	"time"
)

func TestStartStallSweep_SweepsRunStalledMidProcess(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.SetSessionConfig(SessionConfig{
		InFlightPassiveLimit:       1,
		StallTimeoutSeconds:        3600,
		ReverseShareTimeoutSeconds: 1,
	})

	ctx, cancel := context.WithCancel(t.Context())

	// Fresh when seeded: the row crosses the one-second reverse-share budget
	// while the ticker runs, so only a periodic pass can interrupt it.
	runID := "run-stall-ticker"
	seedActiveRunAt(t, core, runID, StateReverseAwaitingShare, time.Now().Unix())

	done := make(chan struct{})

	go func() {
		defer close(done)

		core.startStallSweep(ctx, 10*time.Millisecond)
	}()

	t.Cleanup(func() {
		cancel()
		<-done
	})

	deadline := time.Now().Add(10 * time.Second)

	for {
		got, err := core.GetTestRun(ctx, runID)
		if err != nil {
			t.Fatalf("GetTestRun: %v", err)
		}

		if got.State == StateInterrupted {
			if got.IsActive {
				t.Fatal("is_active = 1, want 0 after the ticker sweep")
			}

			if got.TerminalReason == nil || *got.TerminalReason != ReasonReverseShareTimeout {
				t.Fatalf("terminal_reason = %v, want %q", got.TerminalReason, ReasonReverseShareTimeout)
			}

			break
		}

		if time.Now().After(deadline) {
			t.Fatalf("state = %q, want the periodic sweep to interrupt the wait once it outlives the reverse-share budget", got.State)
		}

		time.Sleep(20 * time.Millisecond)
	}

	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("stall sweep goroutine did not return after cancel")
	}
}

func TestStartStallSweep_HealsTerminalStatsGap(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.SetStatsHostHasher(testStatsHostHasher(t))
	core.SetSessionConfig(SessionConfig{
		InFlightPassiveLimit:       1,
		StallTimeoutSeconds:        3600,
		ReverseShareTimeoutSeconds: 60,
	})

	ctx, cancel := context.WithCancel(t.Context())

	// An opted-in terminal row whose stats write never landed. Nothing on the
	// wait-open path heals it anymore; only the periodic ticker pass can.
	seedTerminalStatsGap(t, core, "run-stall-ticker-heal", "https://peer.example")

	done := make(chan struct{})

	go func() {
		defer close(done)

		core.startStallSweep(ctx, 10*time.Millisecond)
	}()

	t.Cleanup(func() {
		cancel()
		<-done
	})

	deadline := time.Now().Add(10 * time.Second)

	for {
		got, err := core.GetTestRun(ctx, "run-stall-ticker-heal")
		if err != nil {
			t.Fatalf("GetTestRun: %v", err)
		}

		if got.StatsWrittenAt != nil {
			break
		}

		if time.Now().After(deadline) {
			t.Fatal("stats_written_at = nil, want the periodic ticker to heal the missing stats row")
		}

		time.Sleep(20 * time.Millisecond)
	}

	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("stall sweep goroutine did not return after cancel")
	}
}

func TestStartStallSweep_NeverRunsStartupRecovery(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.SetSessionConfig(SessionConfig{
		InFlightPassiveLimit:       1,
		StallTimeoutSeconds:        3600,
		ReverseShareTimeoutSeconds: 60,
	})

	ctx, cancel := context.WithCancel(t.Context())

	// Fresh and inside every inactivity window: a startup-recovery pass would
	// interrupt the row on the first tick; the stall ticker must leave it
	// alone.
	runID := "run-stall-ticker-fresh"
	seedActiveRunAt(t, core, runID, StateCapabilityExercise, time.Now().Unix())

	done := make(chan struct{})

	go func() {
		defer close(done)

		core.startStallSweep(ctx, 10*time.Millisecond)
	}()

	t.Cleanup(func() {
		cancel()
		<-done
	})

	time.Sleep(100 * time.Millisecond)

	got, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if !got.IsActive || got.State != StateCapabilityExercise {
		t.Fatalf("is_active=%v state=%q, want untouched: the ticker never runs startup recovery",
			got.IsActive, got.State)
	}
}
