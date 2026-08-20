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
// minting and binding it on first call. The binding (correlation slot plus
// the active_running -> invite_minted CAS) commits before the product invite
// row is created, so concurrent callers race to one binding winner and later
// callers observe the same canonical invite. A winner that crashes between
// the binding commit and the invite create leaves a bound-but-missing slot;
// the next call heals it deterministically by re-creating the row with the
// bound id and token, so invite_minted never dangles without its invite.
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

	if partyErr := s.ensureSessionPartyA(ctx, run); partyErr != nil {
		return nil, partyErr
	}

	token, err := generateInviteToken()
	if err != nil {
		return nil, err
	}

	inviteID := uuid.NewString()

	if mintErr := s.deps.Store.MintOutgoingInviteBinding(ctx, testRunID, inviteID, token); mintErr != nil {
		if errors.Is(mintErr, validatorcore.ErrShareCorrelationConflict) {
			// A concurrent mint won the slot; return the canonical invite,
			// healing the product row when the winner crashed before create.
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
			return s.storedOutgoingInvite(ctx, inviteID, token)
		}

		// The binding stays committed; the next mint call heals the missing
		// product row through existingOutgoingBinding.
		return nil, fmt.Errorf("reverseinvite: create outgoing invite: %w", err)
	}

	return invite, nil
}

// existingOutgoingBinding loads the invite referenced by the run's outgoing
// correlation slot; ok is false when the slot is still free. A bound slot
// whose product invite row is missing is healed in place, so callers never
// observe invite_minted without its invite.
func (s *Service) existingOutgoingBinding(ctx context.Context, testRunID string) (invite *invitesoutgoing.OutgoingInvite, ok bool, err error) {
	corr, err := s.deps.Store.GetShareCorrelation(ctx, testRunID, validatorcore.RoleOutgoingInvite, validatorcore.LocalIdentityA)
	if errors.Is(err, validatorcore.ErrShareCorrelationNotFound) {
		return nil, false, nil
	}

	if err != nil {
		return nil, false, fmt.Errorf("reverseinvite: load outgoing correlation: %w", err)
	}

	if corr.InviteID == nil || *corr.InviteID == "" || corr.ProviderID == "" {
		return nil, false, ErrCorrelationMismatch
	}

	invite, err = s.deps.OutgoingInvites.GetByID(ctx, *corr.InviteID)
	if err == nil {
		if invite.Token != corr.ProviderID {
			return nil, false, ErrCorrelationMismatch
		}

		return invite, true, nil
	}

	if !errors.Is(err, invites.ErrInviteNotFound) {
		return nil, false, fmt.Errorf("reverseinvite: load bound outgoing invite: %w", err)
	}

	healed, healErr := s.healBoundOutgoingInvite(ctx, corr)
	if healErr != nil {
		return nil, false, healErr
	}

	return healed, true, nil
}

// healBoundOutgoingInvite re-creates the product invite row for a bound
// correlation slot whose winner never stored it. The row is deterministic
// (bound id and token), so concurrent healers converge on one canonical row.
func (s *Service) healBoundOutgoingInvite(ctx context.Context, corr *validatorcore.ShareCorrelation) (*invitesoutgoing.OutgoingInvite, error) {
	invite := s.newOutgoingInvite(*corr.InviteID, corr.ProviderID, corr.TestRunID)
	if err := s.deps.OutgoingInvites.Create(ctx, invite); err != nil {
		if errors.Is(err, store.ErrAlreadyExists) {
			return s.storedOutgoingInvite(ctx, *corr.InviteID, corr.ProviderID)
		}

		return nil, fmt.Errorf("reverseinvite: heal bound outgoing invite: %w", err)
	}

	return invite, nil
}

// storedOutgoingInvite returns the already-stored canonical invite, proving
// the stored row still carries the bound token.
func (s *Service) storedOutgoingInvite(ctx context.Context, inviteID, token string) (*invitesoutgoing.OutgoingInvite, error) {
	stored, err := s.deps.OutgoingInvites.GetByID(ctx, inviteID)
	if err != nil {
		return nil, fmt.Errorf("reverseinvite: load stored outgoing invite: %w", err)
	}

	if stored.Token != token {
		return nil, ErrCorrelationMismatch
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

// ensureSessionPartyA materializes the inviting party the product
// invite-accepted handler looks up when it builds its identity response. The
// party ID is the session run ID so the decorator can prove the accepted
// invite belongs to this run.
func (s *Service) ensureSessionPartyA(ctx context.Context, run *validatorcore.TestRun) error {
	if _, err := s.deps.Parties.Get(ctx, run.TestRunID); err == nil {
		return nil
	} else if !errors.Is(err, identity.ErrUserNotFound) {
		return fmt.Errorf("reverseinvite: get session party: %w", err)
	}

	user := &identity.User{
		ID:          run.TestRunID,
		Username:    "session-inviter-" + run.TestRunID,
		DisplayName: "Session Inviter",
		Role:        identity.RoleProbe,
		Realm:       s.deps.LocalIdentity.ProviderDomain,
		CreatedAt:   time.Now(),
	}
	if err := s.deps.Parties.Create(ctx, user); err != nil {
		if errors.Is(err, identity.ErrUserIDExists) || errors.Is(err, identity.ErrUserExists) {
			return nil
		}

		return fmt.Errorf("reverseinvite: create session party: %w", err)
	}

	return nil
}

func generateInviteToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("reverseinvite: generate invite token: %w", err)
	}

	return hex.EncodeToString(b), nil
}
