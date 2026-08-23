// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"testing"
	"time"
)

func TestTouchUpdatedAt_RefreshesActiveRunWithoutStateChange(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-touch-active"
	stale := time.Now().Unix() - 3600

	if err := core.DB().WithContext(ctx).Create(&TestRun{
		TestRunID:  runID,
		IsActive:   true,
		State:      StateInviteMinted,
		TargetHost: "peer.example",
		CreatedAt:  stale,
		UpdatedAt:  stale,
	}).Error; err != nil {
		t.Fatalf("seed run: %v", err)
	}

	if err := core.TouchUpdatedAt(ctx, runID); err != nil {
		t.Fatalf("TouchUpdatedAt: %v", err)
	}

	got, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if got.State != StateInviteMinted {
		t.Fatalf("state = %q, want invite_minted", got.State)
	}

	if !got.IsActive {
		t.Fatal("is_active = 0, want 1")
	}

	if got.UpdatedAt <= stale {
		t.Fatalf("updated_at = %d, want fresher than %d", got.UpdatedAt, stale)
	}
}

func TestTouchUpdatedAt_TerminalHybridIsNoop(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-touch-terminal"
	stale := time.Now().Unix() - 3600
	reason := ReasonActiveHardFail

	if err := core.DB().WithContext(ctx).Create(&TestRun{
		TestRunID:      runID,
		IsActive:       true,
		State:          StateTerminalFail,
		TargetHost:     "peer.example",
		TerminalReason: &reason,
		CreatedAt:      stale,
		UpdatedAt:      stale,
	}).Error; err != nil {
		t.Fatalf("seed run: %v", err)
	}

	if err := core.TouchUpdatedAt(ctx, runID); err != nil {
		t.Fatalf("TouchUpdatedAt: %v", err)
	}

	got, err := core.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if got.UpdatedAt != stale {
		t.Fatalf("updated_at = %d, want unchanged %d", got.UpdatedAt, stale)
	}

	if got.State != StateTerminalFail {
		t.Fatalf("state = %q, want terminal_fail", got.State)
	}
}
