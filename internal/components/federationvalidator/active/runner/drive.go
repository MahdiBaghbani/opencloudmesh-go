// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package runner

import (
	"context"
	"errors"

	"gorm.io/gorm"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

// DriveOnce inspects the singleton is_active=1 row without narrowing to
// active_running. Missing active work promotes the oldest ready waiter.
func (r *Runner) DriveOnce(ctx context.Context) {
	if r == nil || r.store == nil {
		return
	}

	if err := ctx.Err(); err != nil {
		return
	}

	runID, err := r.store.FindOneActive(ctx, validatorcore.LocalIdentityA)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		r.promoteReadyWaiter(ctx)

		return
	}

	if err != nil {
		r.log.Warn("active runner: load active run", "error", err)

		return
	}

	run, err := r.store.GetTestRun(ctx, runID)
	if err != nil {
		r.log.Warn("active runner: get active run", "test_run_id", runID, "error", err)

		return
	}

	r.driveActive(ctx, run)
}

func (r *Runner) driveActive(ctx context.Context, run *validatorcore.TestRun) {
	switch run.State {
	case validatorcore.StateActiveRunning:
		r.driveFirstMile(ctx, run)
	case validatorcore.StateInviteAccepted:
		r.driveSolicit(ctx, run)
	case validatorcore.StateReverseInviteAccepted:
		r.driveDispatch(ctx, run)
	default:
		r.touchWait(ctx, run)
	}
}

func (r *Runner) promoteReadyWaiter(ctx context.Context) {
	err := r.store.PromoteOldestReadyWaiter(ctx)
	if err == nil || validatorcore.IsActiveSlotBusy(err) {
		return
	}

	if errors.Is(err, validatorcore.ErrSessionNotFound) {
		return
	}

	r.log.Warn("active runner: promote ready waiter", "error", err)
}

func (r *Runner) touchWait(ctx context.Context, run *validatorcore.TestRun) {
	if run == nil {
		return
	}

	if err := r.store.TouchUpdatedAt(ctx, run.TestRunID); err != nil {
		r.log.Warn("active runner: touch updated_at", "test_run_id", run.TestRunID, "error", err)
	}
}
