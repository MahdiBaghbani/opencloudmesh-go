// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"testing"
	"time"
)

func TestPromoteOldestReadyWaiter_SkipsFailEvidenceCASMiss(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	now := time.Now().Unix()
	oldID := "run-fail-ev-old"
	newID := "run-fail-ev-new"

	seedReadyWaiter(t, core, oldID, now-20)
	seedReadyWaiter(t, core, newID, now-5)

	core.SetPromoteAfterSelectHook(func(id string) {
		core.SetPromoteAfterSelectHook(nil)

		if id != oldID {
			t.Fatalf("selected waiter = %q, want %q", id, oldID)
		}

		seedGradedEvidence(t, core, id, SpecificationAreaDiscovery, GradeFail)
	})

	if err := core.PromoteOldestReadyWaiter(ctx); err != nil {
		t.Fatalf("PromoteOldestReadyWaiter: %v", err)
	}

	old, err := core.GetTestRun(ctx, oldID)
	if err != nil {
		t.Fatalf("GetTestRun %s: %v", oldID, err)
	}

	if old.IsActive {
		t.Fatalf("%s took the active lock after fail-evidence CAS miss", oldID)
	}

	if old.State != StatePassiveRunning {
		t.Fatalf("%s state = %q, want %q", oldID, old.State, StatePassiveRunning)
	}

	if old.PassiveReadyAt == nil {
		t.Fatalf("%s lost passive_ready_at after fail-evidence CAS miss", oldID)
	}

	if old.FinishedAt != nil || old.TerminalReason != nil {
		t.Fatalf("%s was terminalized, want skipped stale waiter", oldID)
	}

	assertWaiterPromoted(t, core, newID)
}
