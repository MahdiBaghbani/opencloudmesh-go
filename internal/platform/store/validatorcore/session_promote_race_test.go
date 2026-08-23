// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gorm.io/gorm"
)

func TestPromoteOldestReadyWaiter_SkipsConcurrentlyStoppedWaiter(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	now := time.Now().Unix()

	seedReadyWaiter(t, core, "run-race-old", now-20)
	seedReadyWaiter(t, core, "run-race-new", now-5)
	stopSelectedWaiterOnce(t, core, "run-race-old")

	if err := core.PromoteOldestReadyWaiter(ctx); err != nil {
		t.Fatalf("PromoteOldestReadyWaiter: %v", err)
	}

	assertWaiterStoppedByOperator(t, core, "run-race-old")
	assertWaiterPromoted(t, core, "run-race-new")
}

func TestPromoteOldestReadyWaiter_NoReadyAfterConcurrentStop(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()

	seedReadyWaiter(t, core, "run-race-only", time.Now().Unix())
	stopSelectedWaiterOnce(t, core, "run-race-only")

	if err := core.PromoteOldestReadyWaiter(ctx); err != nil {
		t.Fatalf("PromoteOldestReadyWaiter: %v", err)
	}

	assertWaiterStoppedByOperator(t, core, "run-race-only")

	if _, findErr := core.FindOneActive(ctx, LocalIdentityA); !errors.Is(findErr, gorm.ErrRecordNotFound) {
		t.Fatalf("FindOneActive = %v, want ErrRecordNotFound", findErr)
	}
}

func TestStartupMaintenance_SucceedsWhenSelectedWaiterStopped(t *testing.T) { //nolint:paralleltest // resets the process-local first-maintenance guard
	resetStartupFirstMaintenanceOnce(t)

	core := openTestCore(t)
	core.SetSessionConfig(SessionConfig{
		InFlightPassiveLimit:      10,
		CreatedTTLSeconds:         60,
		PassiveRunningTTLSeconds:  60,
		PassiveCompleteTTLSeconds: 3600,
		TerminalRetentionDays:     30,
		StallTimeoutSeconds:       3600,
	})

	ctx := t.Context()
	now := time.Now().Unix()
	followed := map[string]int{}

	core.SetPromoteFollowUp(func(_ context.Context, id string) bool {
		followed[id]++

		return true
	})

	seedReadyWaiter(t, core, "run-attach-old", now-20)
	seedReadyWaiter(t, core, "run-attach-new", now-5)
	stopSelectedWaiterOnce(t, core, "run-attach-old")

	if err := core.startupMaintenance(ctx); err != nil {
		t.Fatalf("startupMaintenance: %v", err)
	}

	assertWaiterStoppedByOperator(t, core, "run-attach-old")
	assertWaiterPromoted(t, core, "run-attach-new")

	if followed["run-attach-old"] != 0 {
		t.Fatalf("follow-up called for stopped waiter %d times", followed["run-attach-old"])
	}

	if followed["run-attach-new"] != 1 {
		t.Fatalf("follow-up for promoted waiter called %d times, want 1", followed["run-attach-new"])
	}

	if core.LastPromotedID() != "" {
		t.Fatalf("lastPromotedID = %q after delivery, want empty", core.LastPromotedID())
	}
}

func TestPromoteOldestReadyWaiter_FollowUpReplaysAfterBind(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()

	seedReadyWaiter(t, core, "run-replay", time.Now().Unix())

	if err := core.PromoteOldestReadyWaiter(ctx); err != nil {
		t.Fatalf("PromoteOldestReadyWaiter: %v", err)
	}

	assertWaiterPromoted(t, core, "run-replay")

	var got string

	core.SetPromoteFollowUp(func(_ context.Context, id string) bool {
		got = id

		return true
	})
	core.FlushPromoteFollowUp(ctx)

	if got != "run-replay" {
		t.Fatalf("replayed follow-up id = %q, want run-replay", got)
	}

	if core.LastPromotedID() != "" {
		t.Fatalf("lastPromotedID = %q after delivery, want empty", core.LastPromotedID())
	}

	got = ""

	core.FlushPromoteFollowUp(ctx)

	if got != "" {
		t.Fatalf("consumed follow-up replayed id = %q", got)
	}
}

func TestAttach_PromotesWaiterAndReplaysFollowUp(t *testing.T) { //nolint:paralleltest // resets the process-local first-maintenance guard
	resetStartupFirstMaintenanceOnce(t)

	sqlCore := openPeerStore(t)
	ctx := t.Context()

	if err := ApplyValidatorSchema(sqlCore.DB()); err != nil {
		t.Fatalf("ApplyValidatorSchema: %v", err)
	}

	seedReadyWaiter(t, NewCore(sqlCore.DB()), "run-attach-follow", time.Now().Unix())

	core, err := Attach(sqlCore.DB(), DefaultSessionConfig())
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}

	assertWaiterPromoted(t, core, "run-attach-follow")

	var got string

	core.SetPromoteFollowUp(func(_ context.Context, id string) bool {
		got = id

		return true
	})
	core.FlushPromoteFollowUp(ctx)

	if got != "run-attach-follow" {
		t.Fatalf("Attach follow-up id = %q, want run-attach-follow", got)
	}

	if core.LastPromotedID() != "" {
		t.Fatalf("lastPromotedID = %q after delivery, want empty", core.LastPromotedID())
	}
}

func TestPromoteFollowUp_ConcurrentIdempotentCASWinnerOnly(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-cas-once"

	var followed atomic.Int32

	core.SetPromoteFollowUp(func(_ context.Context, id string) bool {
		if id == runID {
			followed.Add(1)
		}

		return true
	})

	seedReadyWaiter(t, core, runID, time.Now().Unix())

	var wg sync.WaitGroup

	start := make(chan struct{})
	errs := make(chan error, 2)

	wg.Add(2)

	go func() {
		defer wg.Done()

		<-start

		errs <- core.PromoteOldestReadyWaiter(ctx)
	}()
	go func() {
		defer wg.Done()

		<-start

		casWon, err := core.ExtendToActiveCAS(ctx, runID)
		if err != nil {
			errs <- err

			return
		}

		if casWon {
			core.notePromotedWaiter(ctx, runID)
		}

		errs <- nil
	}()

	close(start)
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent promote: %v", err)
		}
	}

	assertWaiterPromoted(t, core, runID)

	if followed.Load() != 1 {
		t.Fatalf("follow-up called %d times, want 1", followed.Load())
	}

	if core.LastPromotedID() != "" {
		t.Fatalf("lastPromotedID = %q after delivery, want empty", core.LastPromotedID())
	}
}

func TestPromoteFollowUp_ConcurrentStartupProbeAndFlush(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-pending-race"

	var followed atomic.Int32

	seedReadyWaiter(t, core, runID, time.Now().Unix())

	var wg sync.WaitGroup

	start := make(chan struct{})
	errs := make(chan error, 2)

	wg.Add(3)

	go func() {
		defer wg.Done()

		<-start

		errs <- core.PromoteOldestReadyWaiter(ctx)
	}()
	go func() {
		defer wg.Done()

		<-start

		casWon, err := core.ExtendToActiveCAS(ctx, runID)
		if err != nil {
			errs <- err

			return
		}

		if casWon {
			core.notePromotedWaiter(ctx, runID)
		}

		errs <- nil
	}()
	go func() {
		defer wg.Done()

		<-start

		core.SetPromoteFollowUp(func(_ context.Context, id string) bool {
			if id == runID {
				followed.Add(1)
			}

			return true
		})
		core.FlushPromoteFollowUp(ctx)
	}()

	close(start)
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent pending follow-up: %v", err)
		}
	}

	assertWaiterPromoted(t, core, runID)

	if followed.Load() != 1 {
		t.Fatalf("follow-up called %d times, want 1", followed.Load())
	}

	if core.LastPromotedID() != "" {
		t.Fatalf("lastPromotedID = %q after delivery, want empty", core.LastPromotedID())
	}
}

func stopSelectedWaiterOnce(t *testing.T, core *Core, wantID string) {
	t.Helper()

	core.promoteAfterSelectHook = func(id string) {
		core.promoteAfterSelectHook = nil

		if id != wantID {
			t.Fatalf("selected waiter = %q, want %q", id, wantID)
		}

		if err := core.StopPassive(t.Context(), id); err != nil {
			t.Fatalf("StopPassive %s: %v", id, err)
		}
	}
}

func assertWaiterStoppedByOperator(t *testing.T, core *Core, runID string) {
	t.Helper()

	got, err := core.GetTestRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetTestRun %s: %v", runID, err)
	}

	if got.State != StateTerminalFail {
		t.Fatalf("%s state = %q, want %q", runID, got.State, StateTerminalFail)
	}

	if got.TerminalReason == nil || *got.TerminalReason != ReasonOperatorAborted {
		t.Fatalf("%s terminal_reason = %v, want %q", runID, got.TerminalReason, ReasonOperatorAborted)
	}

	if got.IsActive {
		t.Fatalf("%s must not hold the active lock", runID)
	}
}

func assertWaiterPromoted(t *testing.T, core *Core, runID string) {
	t.Helper()

	got, err := core.GetTestRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetTestRun %s: %v", runID, err)
	}

	if !got.IsActive || got.State != StateActiveRunning {
		t.Fatalf("%s is_active=%v state=%q, want active_running", runID, got.IsActive, got.State)
	}
}
