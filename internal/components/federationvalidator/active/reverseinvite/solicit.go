// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package reverseinvite

import (
	"context"
	"errors"
	"fmt"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
)

// SolicitReverse advances the active run from invite_accepted through
// reverse_invite_solicited to reverse_awaiting_invite. It reuses the Bob
// party bound at session extension and never mints a probe user: when Bob is
// absent from the run or missing from the party repo, the call fails. The
// store op heals an already-solicited crash notch and is idempotent once the
// run is awaiting.
func (s *Service) SolicitReverse(ctx context.Context, testRunID string) error {
	run, err := s.deps.Store.GetTestRun(ctx, testRunID)
	if err != nil {
		return fmt.Errorf("reverseinvite: load test run: %w", err)
	}

	if !run.IsActive {
		return ErrSessionNotActive
	}

	if run.BobUserID == nil || *run.BobUserID == "" {
		return ErrBobNotBound
	}

	if _, err := s.deps.Parties.Get(ctx, *run.BobUserID); err != nil {
		if errors.Is(err, identity.ErrUserNotFound) {
			return ErrBobPartyMissing
		}

		return fmt.Errorf("reverseinvite: load recipient party: %w", err)
	}

	if err := s.deps.Store.SolicitReverse(ctx, testRunID); err != nil {
		return fmt.Errorf("reverseinvite: solicit reverse: %w", err)
	}

	return nil
}
