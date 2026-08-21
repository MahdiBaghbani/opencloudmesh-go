// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package reverseshare

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"

	sharesincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/incoming"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/hostport"
)

// ObserveCreatedShare is the inbound observer hooked into POST /ocm/shares.
// It runs on the fresh create and on the matching idempotent-duplicate path,
// after the share is durably stored and before the 201 is encoded. A reverse
// share addressed to Bob from the session target passes the run; any error is
// retryable and suppresses the 201 so the client's duplicate retry re-enters
// here and heals. Shares that resolve to no run persist normally and never
// touch the run.
func (s *Service) ObserveCreatedShare(ctx context.Context, share *sharesincoming.IncomingShare) error {
	if share == nil {
		return nil
	}

	// The finder matches on the normalized sender authority, the same form
	// inbound handling stores and the run target carries. A stored host that
	// fails normalization can never match; fail closed without suppressing
	// the share create.
	senderHost, normErr := hostport.Normalize(share.SenderHost, s.deps.LocalIdentity.Scheme)
	if normErr != nil {
		s.log.Warn("reverseshare: sender host failed normalization",
			"sender_host", share.SenderHost,
			"error", normErr)

		return nil
	}

	runID, err := s.deps.Store.FindRunByRecipientAndTarget(
		ctx,
		share.RecipientUserID,
		senderHost,
	)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil
	}

	if err != nil {
		return fmt.Errorf("reverseshare: resolve run by recipient and target: %w", err)
	}

	return s.driveReverseShareSuccess(ctx, runID, share.ProviderID)
}
