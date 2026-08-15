// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"context"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

func TestProbeRunner_ReachesPassiveComplete(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	runner := NewProbeRunner(store, nil)
	ctx := context.Background()
	now := time.Now().Unix()
	runID := "run-async-probe"

	row := &validatorcore.TestRun{
		TestRunID:   runID,
		State:       validatorcore.StateCreated,
		SessionKind: validatorcore.SessionKindPassiveOnly,
		TargetHost:  "probe.example",
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := store.CreatePassiveSession(ctx, row); err != nil {
		t.Fatalf("create: %v", err)
	}

	runner.run(ctx, runID)

	got, err := store.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if got.State != validatorcore.StatePassiveComplete {
		t.Fatalf("state = %q, want %q", got.State, validatorcore.StatePassiveComplete)
	}
}
