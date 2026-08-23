// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package runner

import (
	"context"
	"fmt"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/active/reverseinvite"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

func (r *Runner) driveFirstMile(ctx context.Context, run *validatorcore.TestRun) {
	if err := r.ensureBob(ctx, run); err != nil {
		r.handleDriveErr(ctx, run, err)

		return
	}

	if _, err := r.invites.MintOutgoingInvite(ctx, run.TestRunID); err != nil {
		r.handleDriveErr(ctx, run, err)
	}
}

func (r *Runner) driveSolicit(ctx context.Context, run *validatorcore.TestRun) {
	if err := r.ensureBob(ctx, run); err != nil {
		r.handleDriveErr(ctx, run, err)

		return
	}

	if err := r.invites.SolicitReverse(ctx, run.TestRunID); err != nil {
		r.handleDriveErr(ctx, run, err)
	}
}

func (r *Runner) ensureBob(ctx context.Context, run *validatorcore.TestRun) error {
	if run.BobUserID == nil || *run.BobUserID == "" {
		return reverseinvite.ErrBobNotBound
	}

	_, err := identity.EnsureReverseReceiver(ctx, r.parties, identity.ReverseReceiverSpec{
		ID:          *run.BobUserID,
		Email:       r.probeEmail,
		DisplayName: r.probeName,
		Realm:       r.local.ProviderDomain,
	})
	if err != nil {
		return fmt.Errorf("runner: ensure reverse receiver: %w", err)
	}

	return nil
}
