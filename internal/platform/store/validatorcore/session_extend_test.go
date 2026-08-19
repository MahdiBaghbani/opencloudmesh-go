// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"errors"
	"testing"
	"time"
)

func TestExtendToActive_RequiresPassiveComplete(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	now := time.Now().Unix()
	runID := "run-extend-not-ready"

	row := &TestRun{
		TestRunID:   runID,
		State:       StateCreated,
		SessionKind: SessionKindPassiveOnly,
		TargetHost:  "extend.example",
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := core.CreatePassiveSession(ctx, row); err != nil {
		t.Fatalf("create: %v", err)
	}

	err := core.ExtendToActive(ctx, runID)
	if !errors.Is(err, ErrSessionNotReady) {
		t.Fatalf("ExtendToActive error = %v, want ErrSessionNotReady", err)
	}
}

func TestExtendToActive_ConflictsWithOneActiveLock(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	now := time.Now().Unix()

	for _, id := range []string{"run-active-a", "run-active-b"} {
		row := &TestRun{
			TestRunID:   id,
			State:       StatePassiveComplete,
			SessionKind: SessionKindPassiveOnly,
			TargetHost:  "lock.example",
			CreatedAt:   now,
			UpdatedAt:   now,
		}

		if err := core.DB().WithContext(ctx).Create(row).Error; err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}

	if err := core.ExtendToActive(ctx, "run-active-a"); err != nil {
		t.Fatalf("first extend: %v", err)
	}

	extendErr := core.ExtendToActive(ctx, "run-active-b")

	var storeErr *StoreError
	if !errors.As(extendErr, &storeErr) || storeErr.Op != OpExtendUpdate {
		t.Fatalf("second extend error = %v, want OpExtendUpdate store error", extendErr)
	}
}

func TestExtendToActive_TerminalStateReturnsSessionNotReady(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	now := time.Now().Unix()
	runID := "run-extend-terminal"

	row := &TestRun{
		TestRunID:   runID,
		State:       StateTerminalPass,
		SessionKind: SessionKindPassiveOnly,
		TargetHost:  "terminal.example",
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := core.DB().WithContext(ctx).Create(row).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	err := core.ExtendToActive(ctx, runID)
	if !errors.Is(err, ErrSessionNotReady) {
		t.Fatalf("ExtendToActive error = %v, want ErrSessionNotReady", err)
	}

	if errors.Is(err, ErrStopSessionMiss) {
		t.Fatalf("ExtendToActive must not return ErrStopSessionMiss for terminal state")
	}
}

func TestExtendToActive_RepeatedExtensionReturnsInteractiveConflict(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	now := time.Now().Unix()
	runID := "run-repeat-extend"

	row := &TestRun{
		TestRunID:   runID,
		State:       StatePassiveComplete,
		SessionKind: SessionKindPassiveOnly,
		TargetHost:  "repeat.example",
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := core.DB().WithContext(ctx).Create(row).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	if err := core.ExtendToActive(ctx, runID); err != nil {
		t.Fatalf("first extend: %v", err)
	}

	err := core.ExtendToActive(ctx, runID)
	if !errors.Is(err, ErrInteractiveRunInProgress) {
		t.Fatalf("repeat extend error = %v, want ErrInteractiveRunInProgress", err)
	}
}
