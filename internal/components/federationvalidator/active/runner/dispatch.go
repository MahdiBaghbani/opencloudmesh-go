// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package runner

import (
	"context"
	"errors"
	"fmt"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/address"
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/hostport"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

func (r *Runner) driveDispatch(ctx context.Context, run *validatorcore.TestRun) {
	creator := r.outgoingCreator()
	if creator == nil {
		r.log.Warn("active runner: outgoing creator is not bound", "test_run_id", run.TestRunID)
		r.touchWait(ctx, run)

		return
	}

	alice, err := identity.EnsureSessionInviter(ctx, r.parties, run.TestRunID, r.local.ProviderDomain)
	if err != nil {
		r.handleDriveErr(ctx, run, err)

		return
	}

	req, err := designatedShareRequest(run, r.probePath, r.local.Scheme)
	if err != nil {
		r.handleDriveErr(ctx, run, err)

		return
	}

	if _, err := creator.CreateAsUser(ctx, alice, req); err != nil {
		r.handleDriveErr(ctx, run, err)
	}
}

func designatedShareRequest(
	run *validatorcore.TestRun,
	probePath, scheme string,
) (sharesoutgoing.OutgoingShareRequest, error) {
	shareWith, err := designatedShareWith(run, scheme)
	if err != nil {
		return sharesoutgoing.OutgoingShareRequest{}, err
	}

	if probePath == "" {
		return sharesoutgoing.OutgoingShareRequest{}, errors.New("runner: probe file path is required")
	}

	return sharesoutgoing.OutgoingShareRequest{
		ReceiverDomain: run.TargetHost,
		ShareWith:      shareWith,
		LocalPath:      probePath,
		Permissions:    append([]string{}, spec.SupportedWebDAVPermissions...),
	}, nil
}

func designatedShareWith(run *validatorcore.TestRun, scheme string) (string, error) {
	if run.DesignatedShareWith == nil || *run.DesignatedShareWith == "" {
		return "", fmt.Errorf("runner: %w", validatorcore.ErrShareCorrelationConflict)
	}

	raw := *run.DesignatedShareWith

	user, provider, err := address.Parse(raw)
	if err != nil {
		user, provider = raw, run.TargetHost
	}

	normalized, err := hostport.Normalize(provider, scheme)
	if err != nil || normalized != run.TargetHost {
		return "", fmt.Errorf("runner: %w", validatorcore.ErrShareCorrelationConflict)
	}

	return user + "@" + normalized, nil
}
