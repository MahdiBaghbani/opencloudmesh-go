// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package repos

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
	invitesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
)

// outgoingInviteAdapter adapts store.OutgoingInviteStore to
// invitesoutgoing.OutgoingInviteRepo.
type outgoingInviteAdapter struct {
	s store.OutgoingInviteStore
}

var _ invitesoutgoing.OutgoingInviteRepo = (*outgoingInviteAdapter)(nil)

func (a *outgoingInviteAdapter) Create(ctx context.Context, invite *invitesoutgoing.OutgoingInvite) error {
	if invite.ID == "" {
		invite.ID = uuid.New().String()
	}

	if invite.CreatedAt.IsZero() {
		invite.CreatedAt = time.Now()
	}

	if invite.Status == "" {
		invite.Status = invites.InviteStatusPending
	}

	if err := invites.ValidateCreateInviteStatus(string(invite.Status), invite.AcceptedUserID, invite.AcceptedProviderFQDNNormalized); err != nil {
		return err
	}

	s := appOutgoingInviteToStore(invite)
	if err := a.s.CreateOutgoingInvite(ctx, s); err != nil {
		if errors.Is(err, store.ErrAlreadyExists) {
			return fmt.Errorf("invite already exists: %w", store.ErrAlreadyExists)
		}

		return err
	}

	return nil
}

func (a *outgoingInviteAdapter) GetByID(ctx context.Context, id string) (*invitesoutgoing.OutgoingInvite, error) {
	s, err := a.s.GetOutgoingInvite(ctx, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, invites.ErrInviteNotFound
		}

		return nil, err
	}

	return storeOutgoingInviteToApp(s), nil
}

func (a *outgoingInviteAdapter) GetByToken(ctx context.Context, token string) (*invitesoutgoing.OutgoingInvite, error) {
	s, err := a.s.GetOutgoingInviteByToken(ctx, token)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, invites.ErrTokenNotFound
		}

		return nil, err
	}

	return storeOutgoingInviteToApp(s), nil
}

func (a *outgoingInviteAdapter) List(ctx context.Context) ([]*invitesoutgoing.OutgoingInvite, error) {
	// Pass empty userID to list all invites (matches memory repo behaviour).
	storeInvites, err := a.s.ListOutgoingInvites(ctx, "")
	if err != nil {
		return nil, err
	}

	result := make([]*invitesoutgoing.OutgoingInvite, 0, len(storeInvites))
	for _, s := range storeInvites {
		result = append(result, storeOutgoingInviteToApp(s))
	}

	return result, nil
}

func (a *outgoingInviteAdapter) UpdateStatus(
	ctx context.Context,
	id string,
	status invites.InviteStatus,
	acceptance *invitesoutgoing.Acceptance,
) error {
	existing, err := a.s.GetOutgoingInvite(ctx, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return invites.ErrInviteNotFound
		}

		return err
	}

	argUserID := ""
	argHost := ""

	if acceptance != nil {
		argUserID = acceptance.UserID
		argHost = acceptance.ProviderFQDNNormalized
	}

	if err := invites.ValidateUpdateAcceptedIdentity(string(status), argUserID, argHost, existing.AcceptedUserID, existing.AcceptedProviderFQDNNormalized); err != nil {
		return err
	}

	existing.Status = string(status)
	existing.AcceptedUserID, existing.AcceptedProviderFQDNNormalized = invites.CoalesceAcceptedIdentity(
		argUserID, argHost, existing.AcceptedUserID, existing.AcceptedProviderFQDNNormalized)

	if acceptance != nil {
		// The raw provider FQDN keeps replace semantics: only the user id and
		// the normalized host coalesce with the stored identity above.
		if strings.TrimSpace(acceptance.ProviderFQDN) != "" {
			existing.AcceptedProviderFQDN = acceptance.ProviderFQDN
		}

		existing.AcceptedAt = time.Now().Unix()
	}

	if err := a.s.UpdateOutgoingInvite(ctx, existing); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return invites.ErrInviteNotFound
		}

		return err
	}

	return nil
}

// FindAcceptedForRecipient finds an accepted outgoing invite created by the
// local sender whose remote accepter matches both the given user and
// normalized host. Rows without a persisted normalized provider host never
// match.
func (a *outgoingInviteAdapter) FindAcceptedForRecipient(
	ctx context.Context,
	senderUserID string,
	recipientUserID string,
	recipientFQDNNormalized string,
) (*invitesoutgoing.OutgoingInvite, error) {
	// Pass empty userID to list all invites (matches List behaviour).
	storeInvites, err := a.s.ListOutgoingInvites(ctx, "")
	if err != nil {
		return nil, err
	}

	for _, s := range storeInvites {
		if s.Status != string(invites.InviteStatusAccepted) {
			continue
		}

		if s.CreatedByUserID != senderUserID || s.AcceptedUserID != recipientUserID {
			continue
		}

		// Rows without a persisted normalized provider host never match, even
		// against an empty query value.
		if s.AcceptedProviderFQDNNormalized == "" || s.AcceptedProviderFQDNNormalized != recipientFQDNNormalized {
			continue
		}

		return storeOutgoingInviteToApp(s), nil
	}

	return nil, invites.ErrInviteNotFound
}

// storeOutgoingInviteToApp converts a store model to the app-layer model.
func storeOutgoingInviteToApp(s *store.OutgoingInvite) *invitesoutgoing.OutgoingInvite {
	return &invitesoutgoing.OutgoingInvite{
		ID:              s.ID,
		Token:           s.Token,
		ProviderFQDN:    s.ProviderFQDN,
		InviteString:    s.InviteString,
		RecipientEmail:  s.RecipientEmail,
		CreatedByUserID: s.CreatedByUserID,
		CreatedAt:       unixToTime(s.CreatedAt),
		ExpiresAt:       unixToTime(s.ExpiresAt),
		Status:          invites.InviteStatus(s.Status),
		AcceptedAt:      unixToTimePtr(s.AcceptedAt),

		AcceptedProviderFQDN:           s.AcceptedProviderFQDN,
		AcceptedUserID:                 s.AcceptedUserID,
		AcceptedProviderFQDNNormalized: s.AcceptedProviderFQDNNormalized,
	}
}

// appOutgoingInviteToStore converts an app-layer model to the store model.
func appOutgoingInviteToStore(a *invitesoutgoing.OutgoingInvite) *store.OutgoingInvite {
	return &store.OutgoingInvite{
		ID:              a.ID,
		Token:           a.Token,
		ProviderFQDN:    a.ProviderFQDN,
		InviteString:    a.InviteString,
		RecipientEmail:  a.RecipientEmail,
		CreatedByUserID: a.CreatedByUserID,
		Status:          string(a.Status),
		ExpiresAt:       timeToUnix(a.ExpiresAt),
		CreatedAt:       timeToUnix(a.CreatedAt),
		AcceptedAt:      timePtrToUnix(a.AcceptedAt),

		AcceptedProviderFQDN:           a.AcceptedProviderFQDN,
		AcceptedUserID:                 a.AcceptedUserID,
		AcceptedProviderFQDNNormalized: a.AcceptedProviderFQDNNormalized,
	}
}
