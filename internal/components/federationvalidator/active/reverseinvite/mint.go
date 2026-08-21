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
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

// outgoingInviteTTL bounds how long a minted session invite stays redeemable.
const outgoingInviteTTL = 24 * time.Hour

// MintOutgoingInvite returns the run's single canonical outgoing invite,
// minting and binding it on first call. The binding (outgoing_invite_id plus
// the active_running -> invite_minted CAS) commits before the product invite
// row is created, so concurrent callers race to one binding winner and later
// callers observe the same canonical invite. A winner that crashes between
// the binding commit and the invite create leaves a bound-but-missing id;
// the next call heals it by re-creating the product row with the bound id.
func (s *Service) MintOutgoingInvite(ctx context.Context, testRunID string) (*invitesoutgoing.OutgoingInvite, error) {
	run, err := s.deps.Store.GetTestRun(ctx, testRunID)
	if err != nil {
		return nil, fmt.Errorf("reverseinvite: load test run: %w", err)
	}

	if !run.IsActive {
		return nil, ErrSessionNotActive
	}

	bound, ok, bindErr := s.existingOutgoingBinding(ctx, testRunID)
	if bindErr != nil {
		return nil, bindErr
	}

	if ok {
		return bound, nil
	}

	if _, partyErr := identity.EnsureSessionInviter(
		ctx,
		s.deps.Parties,
		run.TestRunID,
		s.deps.LocalIdentity.ProviderDomain,
	); partyErr != nil {
		return nil, fmt.Errorf("reverseinvite: ensure session inviter: %w", partyErr)
	}

	token, err := generateInviteToken()
	if err != nil {
		return nil, err
	}

	inviteID := uuid.NewString()

	if mintErr := s.deps.Store.MintOutgoingInviteBinding(ctx, testRunID, inviteID, token); mintErr != nil {
		if errors.Is(mintErr, validatorcore.ErrShareCorrelationConflict) {
			// A concurrent mint won the outgoing invite id; return the
			// canonical invite, healing the product row when the winner
			// crashed before create.
			bound, found, lookupErr := s.existingOutgoingBinding(ctx, testRunID)
			if lookupErr != nil {
				return nil, lookupErr
			}

			if found {
				return bound, nil
			}
		}

		return nil, fmt.Errorf("reverseinvite: bind outgoing invite: %w", mintErr)
	}

	invite := s.newOutgoingInvite(inviteID, token, testRunID)
	if err := s.deps.OutgoingInvites.Create(ctx, invite); err != nil {
		if errors.Is(err, store.ErrAlreadyExists) {
			// A concurrent healer stored the canonical invite first.
			// The bound id is the identity; the healer may have minted a
			// fresh token because the run does not persist the original.
			return s.storedOutgoingInviteByID(ctx, inviteID)
		}

		// The binding stays committed; the next mint call heals the missing
		// product row through existingOutgoingBinding.
		return nil, fmt.Errorf("reverseinvite: create outgoing invite: %w", err)
	}

	return invite, nil
}

// existingOutgoingBinding loads the invite referenced by the run's
// outgoing_invite_id; ok is false when the pointer is still empty. A bound
// id whose product invite row is missing is healed in place, so callers
// never observe invite_minted without its invite.
func (s *Service) existingOutgoingBinding(ctx context.Context, testRunID string) (invite *invitesoutgoing.OutgoingInvite, ok bool, err error) {
	run, err := s.deps.Store.GetTestRun(ctx, testRunID)
	if err != nil {
		return nil, false, fmt.Errorf("reverseinvite: load test run: %w", err)
	}

	if run.OutgoingInviteID == nil || *run.OutgoingInviteID == "" {
		return nil, false, nil
	}

	inviteID := *run.OutgoingInviteID

	invite, err = s.deps.OutgoingInvites.GetByID(ctx, inviteID)
	if err == nil {
		return invite, true, nil
	}

	if !errors.Is(err, invites.ErrInviteNotFound) {
		return nil, false, fmt.Errorf("reverseinvite: load bound outgoing invite: %w", err)
	}

	healed, healErr := s.healBoundOutgoingInvite(ctx, testRunID, inviteID)
	if healErr != nil {
		return nil, false, healErr
	}

	return healed, true, nil
}

// healBoundOutgoingInvite re-creates the product invite row for a bound
// outgoing_invite_id whose winner never stored it. The validator row does
// not keep the original token, so the healer mints a fresh token for the
// same id. Concurrent healers converge on one canonical row.
func (s *Service) healBoundOutgoingInvite(ctx context.Context, testRunID, inviteID string) (*invitesoutgoing.OutgoingInvite, error) {
	token, err := generateInviteToken()
	if err != nil {
		return nil, err
	}

	invite := s.newOutgoingInvite(inviteID, token, testRunID)
	if err := s.deps.OutgoingInvites.Create(ctx, invite); err != nil {
		if errors.Is(err, store.ErrAlreadyExists) {
			return s.storedOutgoingInviteByID(ctx, inviteID)
		}

		return nil, fmt.Errorf("reverseinvite: heal bound outgoing invite: %w", err)
	}

	return invite, nil
}

func (s *Service) storedOutgoingInviteByID(ctx context.Context, inviteID string) (*invitesoutgoing.OutgoingInvite, error) {
	stored, err := s.deps.OutgoingInvites.GetByID(ctx, inviteID)
	if err != nil {
		return nil, fmt.Errorf("reverseinvite: load stored outgoing invite: %w", err)
	}

	return stored, nil
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
