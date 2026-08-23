// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package runner

import (
	"context"
	"errors"

	outgoingshares "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api/outgoing/shares"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/active/reverseinvite"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

func (r *Runner) handleDriveErr(ctx context.Context, run *validatorcore.TestRun, err error) {
	if err == nil {
		return
	}

	if errors.Is(err, outgoingshares.ErrDispatchInProgress) {
		r.touchWait(ctx, run)

		return
	}

	if reason, hard := classifyHardFail(err); hard {
		r.writeHardFail(ctx, run.TestRunID, reason, err)

		return
	}

	r.log.Warn("active runner: retryable drive error", "test_run_id", run.TestRunID, "error", err)
	r.touchWait(ctx, run)
}

func classifyHardFail(err error) (string, bool) {
	switch {
	case errors.Is(err, validatorcore.ErrShareCorrelationConflict),
		errors.Is(err, reverseinvite.ErrCorrelationMismatch):
		return validatorcore.ReasonActiveHardFailCorrelation, true
	case errors.Is(err, identity.ErrPartyIdentityMismatch),
		errors.Is(err, identity.ErrUserExists),
		errors.Is(err, identity.ErrEmailExists),
		errors.Is(err, reverseinvite.ErrBobNotBound),
		errors.Is(err, reverseinvite.ErrBobPartyMissing):
		return validatorcore.ReasonActiveHardFailIdentity, true
	case errors.Is(err, outgoingshares.ErrDispatchRefused):
		return validatorcore.ReasonActiveHardFailDispatch, true
	default:
		return "", false
	}
}

func (r *Runner) writeHardFail(ctx context.Context, testRunID, reason string, cause error) {
	if failErr := r.store.ReleaseActiveHardFail(ctx, testRunID, reason); failErr != nil {
		r.log.Warn(
			"active runner: hard-fail write failed",
			"test_run_id", testRunID,
			"reason", reason,
			"error", failErr,
			"cause", cause,
		)

		return
	}

	r.log.Warn("active runner: hard-failed run", "test_run_id", testRunID, "reason", reason, "error", cause)
}
