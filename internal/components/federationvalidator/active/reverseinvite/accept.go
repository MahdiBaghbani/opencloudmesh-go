// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package reverseinvite

import (
	"context"
	"fmt"
	"net/http"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/address"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
	invitesincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/incoming"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/hostport"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

// AcceptIncoming runs the validator's reverse-invite acceptance: it proves
// the exact RoleIncomingInvite correlation for the active run, reuses the
// live incoming-accept domain operations to notify the sender as Bob and
// persist the accepted status, then heals AcceptReverseInvite (already
// advanced by the paste). A locally already-accepted invite skips the
// outbound call and only heals the same correlated invite ID.
func (s *Service) AcceptIncoming(ctx context.Context, testRunID string) error {
	run, invite, err := s.exactIncomingCorrelation(ctx, testRunID)
	if err != nil {
		return err
	}

	bobID := *run.BobUserID

	senderNormalized, err := hostport.Normalize(invite.SenderFQDN, s.deps.LocalIdentity.Scheme)
	if err != nil {
		return fmt.Errorf("reverseinvite: normalize sender host: %w", err)
	}

	if senderNormalized != run.TargetHost {
		return ErrCorrelationMismatch
	}

	if invite.Status == invites.InviteStatusAccepted {
		// Retry after a crash between the remote accept and the local CAS:
		// heal the same correlated invite ID, never pick another invite.
		if recErr := s.recordOutgoingInviteAccepted(ctx, testRunID, 0); recErr != nil {
			return recErr
		}

		return s.acceptReverseCAS(ctx, testRunID)
	}

	bob, err := s.deps.Parties.Get(ctx, bobID)
	if err != nil {
		return fmt.Errorf("reverseinvite: load recipient party: %w", err)
	}

	reqBody := spec.InviteAcceptedRequest{
		RecipientProvider: s.deps.LocalIdentity.ProviderDomain,
		Token:             invite.Token,
		UserID:            address.EncodeFederatedOpaqueID(bob.ID, s.deps.LocalIdentity.ProviderDomain),
		Email:             bob.Email,
		Name:              bob.DisplayName,
	}

	result, err := invitesincoming.SendInviteAccepted(ctx, s.deps.Poster, reqBody, invite.SenderFQDN)
	if err != nil {
		return fmt.Errorf("reverseinvite: send invite-accepted: %w", err)
	}

	// A 409 carrying the sender identity arrives as AlreadyAccepted: idempotent
	// success that persists and heals the exact correlated invite.
	acceptance := &invitesincoming.Acceptance{
		UserID:                 result.Response.UserID,
		ProviderFQDN:           invite.SenderFQDN,
		ProviderFQDNNormalized: senderNormalized,
	}
	if err := s.deps.IncomingInvites.UpdateStatusForRecipientUserID(
		ctx, invite.ID, bobID, invites.InviteStatusAccepted, acceptance,
	); err != nil {
		return fmt.Errorf("reverseinvite: persist invite acceptance: %w", err)
	}

	status := http.StatusOK
	if result.AlreadyAccepted {
		status = http.StatusConflict
	}

	if err := s.recordOutgoingInviteAccepted(ctx, testRunID, status); err != nil {
		return err
	}

	return s.acceptReverseCAS(ctx, testRunID)
}

func (s *Service) recordOutgoingInviteAccepted(ctx context.Context, testRunID string, status int) error {
	if err := s.deps.Store.PersistActiveExchangeAndFact(
		ctx,
		validatorcore.OutgoingInviteAcceptedExchange(testRunID, status),
		validatorcore.ReverseInviteAcceptedFact(testRunID, nil),
	); err != nil {
		return fmt.Errorf("reverseinvite: record outgoing invite-accepted: %w", err)
	}

	return nil
}

// exactIncomingCorrelation proves the active run, its RoleIncomingInvite
// correlation row, and the referenced incoming invite agree exactly on token,
// invite ID, and Bob recipient before any accept traffic flows.
func (s *Service) exactIncomingCorrelation(
	ctx context.Context,
	testRunID string,
) (*validatorcore.TestRun, *invitesincoming.IncomingInvite, error) {
	run, err := s.deps.Store.GetTestRun(ctx, testRunID)
	if err != nil {
		return nil, nil, fmt.Errorf("reverseinvite: load test run: %w", err)
	}

	if !run.IsActive {
		return nil, nil, ErrSessionNotActive
	}

	if run.BobUserID == nil || *run.BobUserID == "" {
		return nil, nil, ErrBobNotBound
	}

	corr, err := s.deps.Store.GetShareCorrelation(ctx, testRunID, validatorcore.RoleIncomingInvite, validatorcore.LocalIdentityB)
	if err != nil {
		return nil, nil, fmt.Errorf("reverseinvite: load incoming correlation: %w", err)
	}

	if corr.InviteID == nil || *corr.InviteID == "" || corr.ProviderID == "" {
		return nil, nil, ErrCorrelationMismatch
	}

	if run.ReverseInviteToken == nil || *run.ReverseInviteToken != corr.ProviderID {
		return nil, nil, ErrCorrelationMismatch
	}

	invite, err := s.deps.IncomingInvites.GetByIDForRecipientUserID(ctx, *corr.InviteID, *run.BobUserID)
	if err != nil {
		return nil, nil, fmt.Errorf("reverseinvite: load correlated incoming invite: %w", err)
	}

	if invite.Token != corr.ProviderID || invite.RecipientUserID != *run.BobUserID {
		return nil, nil, ErrCorrelationMismatch
	}

	return run, invite, nil
}

// acceptReverseCAS runs the winning-CAS accept advance and wraps failures
// without hiding the sentinel transition errors the paste route maps.
func (s *Service) acceptReverseCAS(ctx context.Context, testRunID string) error {
	if err := s.deps.Store.AcceptReverseInvite(ctx, testRunID); err != nil {
		return fmt.Errorf("reverseinvite: accept reverse invite CAS: %w", err)
	}

	return nil
}
