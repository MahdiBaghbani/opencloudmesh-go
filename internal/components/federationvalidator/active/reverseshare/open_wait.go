// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package reverseshare

import (
	"context"
	"errors"
	"fmt"

	sharesincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/incoming"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/hostport"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

// OpenReverseShareWait opens the event-driven reverse-share wait after the
// capability exercise durably advanced the run. It is callable from the
// post-exercise hook and from poll heal; both call only when the loaded state
// is capability_exercise, and every other state is a no-op here so the two
// call sites need no coordination. Before the wait opens, Bob's inbox is
// checked for an early-arrived share, which passes the run immediately; after
// the CAS a second inbox scan closes the arrival window between the first
// scan and the state transition. The wait itself is the stall sweep's
// reverse_share_timeout; this function never blocks and never starts timers.
func (s *Service) OpenReverseShareWait(ctx context.Context, testRunID string) error {
	run, err := s.deps.Store.GetTestRun(ctx, testRunID)
	if errors.Is(err, validatorcore.ErrSessionNotFound) {
		return nil
	}

	if err != nil {
		return fmt.Errorf("reverseshare: load run: %w", err)
	}

	if !run.IsActive || run.State != validatorcore.StateCapabilityExercise {
		return nil
	}

	share, arrived, err := s.findArrivedReverseShare(ctx, run)
	if err != nil {
		return err
	}

	if arrived {
		return s.driveReverseShareSuccess(ctx, run.TestRunID, share.ProviderID)
	}

	if openErr := s.deps.Store.OpenReverseAwaitingShare(ctx, testRunID); openErr != nil {
		if !errors.Is(openErr, validatorcore.ErrStateTransitionMiss) {
			return fmt.Errorf("reverseshare: open wait: %w", openErr)
		}
		// A concurrent transition won the race; the post-CAS scan below still
		// closes the arrival window.
	}

	share, arrived, err = s.findArrivedReverseShare(ctx, run)
	if err != nil {
		return err
	}

	if arrived {
		return s.driveReverseShareSuccess(ctx, run.TestRunID, share.ProviderID)
	}

	return nil
}

// findArrivedReverseShare lists Bob's inbox and returns the first share whose
// sender host, normalized scheme-aware with the local scheme, matches the
// run's target host. This is the same normalized-authority rule inbound
// handling applies when it stores the share, so default-port forms of the
// target authority match and non-default ports of any other authority never
// do. Occupancy of reverse_share_provider_id is never consulted as proof of
// arrival.
func (s *Service) findArrivedReverseShare(
	ctx context.Context,
	run *validatorcore.TestRun,
) (*sharesincoming.IncomingShare, bool, error) {
	if run.BobUserID == nil || *run.BobUserID == "" {
		return nil, false, nil
	}

	shares, err := s.deps.IncomingShares.ListByRecipientUserID(ctx, *run.BobUserID)
	if err != nil {
		return nil, false, fmt.Errorf("reverseshare: list recipient inbox: %w", err)
	}

	for _, share := range shares {
		senderHost, normErr := hostport.Normalize(share.SenderHost, s.deps.LocalIdentity.Scheme)
		if normErr != nil {
			// A stored host that fails normalization can never match the
			// target; skip it without failing the whole inbox scan.
			s.log.Warn("reverseshare: inbox sender host failed normalization",
				"sender_host", share.SenderHost,
				"error", normErr)

			continue
		}

		if senderHost == run.TargetHost {
			return share, true, nil
		}
	}

	return nil, false, nil
}
