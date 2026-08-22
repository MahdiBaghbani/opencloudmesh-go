// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package reverseinvite

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
	invitesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

// outgoingInviteTTL bounds how long a minted session invite stays redeemable.
const outgoingInviteTTL = 24 * time.Hour

// MintOutgoingInvite returns the run's single canonical outgoing invite,
// minting and binding it on first call. Insert, pointer bind, and the
// active_running -> invite_minted CAS share one transaction. Retry and
// concurrent losers load the already-bound invite by pointer and never
// remint. Mint does not write s1_claimed_at.
//
// The product POST /api/invites/outgoing handler remains a second invite
// token writer for ordinary peer use. Session mint is the validator writer
// for the run's canonical outgoing invite.
func (s *Service) MintOutgoingInvite(ctx context.Context, testRunID string) (*invitesoutgoing.OutgoingInvite, error) {
	run, err := s.deps.Store.GetTestRun(ctx, testRunID)
	if err != nil {
		return nil, fmt.Errorf("reverseinvite: load test run: %w", err)
	}

	if !run.IsActive {
		return nil, ErrSessionNotActive
	}

	bound, lookupErr := s.lookupBoundOutgoingInvite(ctx, run)
	if lookupErr == nil {
		return bound, nil
	}

	if !errors.Is(lookupErr, errOutgoingInviteUnbound) {
		return nil, lookupErr
	}

	if _, partyErr := identity.EnsureSessionInviter(
		ctx,
		s.deps.Parties,
		run.TestRunID,
		s.deps.LocalIdentity.ProviderDomain,
	); partyErr != nil {
		return nil, fmt.Errorf("reverseinvite: ensure session inviter: %w", partyErr)
	}

	return s.mintNewOutgoingInvite(ctx, testRunID)
}

func (s *Service) mintNewOutgoingInvite(
	ctx context.Context,
	testRunID string,
) (*invitesoutgoing.OutgoingInvite, error) {
	token, err := generateInviteToken()
	if err != nil {
		return nil, err
	}

	invite := s.newOutgoingInvite(uuid.NewString(), token, testRunID)

	mintErr := s.deps.Store.MintOutgoingInvite(ctx, testRunID, outgoingInviteMint(invite))
	if mintErr == nil {
		return s.reloadBoundOutgoingInvite(ctx, testRunID, invite)
	}

	if recovered, ok := s.recoverMintConflict(ctx, testRunID, mintErr); ok {
		return recovered, nil
	}

	return nil, fmt.Errorf("reverseinvite: mint outgoing invite: %w", mintErr)
}

var errOutgoingInviteUnbound = errors.New("reverseinvite: outgoing invite is not bound")

func (s *Service) lookupBoundOutgoingInvite(
	ctx context.Context,
	run *validatorcore.TestRun,
) (*invitesoutgoing.OutgoingInvite, error) {
	if run.OutgoingInviteID == nil || *run.OutgoingInviteID == "" {
		return nil, errOutgoingInviteUnbound
	}

	invite, err := s.deps.OutgoingInvites.GetByID(ctx, *run.OutgoingInviteID)
	if err != nil {
		return nil, fmt.Errorf("reverseinvite: load bound outgoing invite: %w", err)
	}

	return invite, nil
}

func (s *Service) reloadBoundOutgoingInvite(
	ctx context.Context,
	testRunID string,
	fallback *invitesoutgoing.OutgoingInvite,
) (*invitesoutgoing.OutgoingInvite, error) {
	run, err := s.deps.Store.GetTestRun(ctx, testRunID)
	if err == nil {
		bound, lookupErr := s.lookupBoundOutgoingInvite(ctx, run)
		if lookupErr == nil {
			return bound, nil
		}
	}

	return fallback, nil
}

func (s *Service) recoverMintConflict(
	ctx context.Context,
	testRunID string,
	mintErr error,
) (*invitesoutgoing.OutgoingInvite, bool) {
	if !errors.Is(mintErr, validatorcore.ErrShareCorrelationConflict) {
		return nil, false
	}

	run, err := s.deps.Store.GetTestRun(ctx, testRunID)
	if err != nil {
		return nil, false
	}

	bound, lookupErr := s.lookupBoundOutgoingInvite(ctx, run)
	if lookupErr != nil {
		return nil, false
	}

	return bound, true
}

func outgoingInviteMint(invite *invitesoutgoing.OutgoingInvite) validatorcore.OutgoingInviteMint {
	return validatorcore.OutgoingInviteMint{
		ID:              invite.ID,
		Token:           invite.Token,
		ProviderFQDN:    invite.ProviderFQDN,
		InviteString:    invite.InviteString,
		CreatedByUserID: invite.CreatedByUserID,
		Status:          string(invite.Status),
		CreatedAt:       invite.CreatedAt.Unix(),
		ExpiresAt:       invite.ExpiresAt.Unix(),
	}
}

// newOutgoingInvite builds the canonical pending invite row for a run.
func (s *Service) newOutgoingInvite(inviteID, token, createdBy string) *invitesoutgoing.OutgoingInvite {
	return &invitesoutgoing.OutgoingInvite{
		ID:              inviteID,
		Token:           token,
		ProviderFQDN:    s.deps.LocalIdentity.ProviderDomain,
		InviteString:    invites.BuildInviteString(token, s.deps.LocalIdentity.ProviderDomain),
		CreatedByUserID: createdBy,
		CreatedAt:       time.Now(),
		ExpiresAt:       time.Now().Add(outgoingInviteTTL),
		Status:          invites.InviteStatusPending,
	}
}

func generateInviteToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("reverseinvite: generate invite token: %w", err)
	}

	return hex.EncodeToString(b), nil
}
