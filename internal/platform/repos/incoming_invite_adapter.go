// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package repos

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
	invitesincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/incoming"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
)

// incomingInviteAdapter adapts store.IncomingInviteStore to
// invitesincoming.IncomingInviteRepo.
type incomingInviteAdapter struct {
	s store.IncomingInviteStore
}

var _ invitesincoming.IncomingInviteRepo = (*incomingInviteAdapter)(nil)

func (a *incomingInviteAdapter) Create(ctx context.Context, invite *invitesincoming.IncomingInvite) error {
	if invite.ID == "" {
		invite.ID = uuid.New().String()
	}

	if invite.ReceivedAt.IsZero() {
		invite.ReceivedAt = time.Now()
	}

	if invite.Status == "" {
		invite.Status = invites.InviteStatusPending
	}

	if err := invites.ValidateCreateInviteStatus(string(invite.Status), invite.SenderUserID, invite.SenderFQDNNormalized); err != nil {
		return err
	}

	s := appIncomingInviteToStore(invite)
	if err := a.s.CreateIncomingInvite(ctx, s); err != nil {
		if errors.Is(err, store.ErrAlreadyExists) {
			return fmt.Errorf("invite already exists: %w", store.ErrAlreadyExists)
		}

		return err
	}

	return nil
}

func (a *incomingInviteAdapter) GetByIDForRecipientUserID(
	ctx context.Context,
	id string,
	recipientUserID string,
) (*invitesincoming.IncomingInvite, error) {
	s, err := a.s.GetIncomingInviteForRecipient(ctx, id, recipientUserID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, invites.ErrInviteNotFound
		}

		return nil, err
	}

	return storeIncomingInviteToApp(s), nil
}

func (a *incomingInviteAdapter) GetByTokenForRecipientUserID(
	ctx context.Context,
	token string,
	recipientUserID string,
) (*invitesincoming.IncomingInvite, error) {
	s, err := a.s.GetIncomingInviteByToken(ctx, token, recipientUserID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, invites.ErrInviteNotFound
		}

		return nil, err
	}

	return storeIncomingInviteToApp(s), nil
}

func (a *incomingInviteAdapter) ListByRecipientUserID(
	ctx context.Context,
	recipientUserID string,
) ([]*invitesincoming.IncomingInvite, error) {
	storeInvites, err := a.s.ListIncomingInvites(ctx, recipientUserID)
	if err != nil {
		return nil, err
	}

	result := make([]*invitesincoming.IncomingInvite, 0, len(storeInvites))
	for _, s := range storeInvites {
		result = append(result, storeIncomingInviteToApp(s))
	}

	return result, nil
}

func (a *incomingInviteAdapter) UpdateStatusForRecipientUserID(
	ctx context.Context,
	id string,
	recipientUserID string,
	status invites.InviteStatus,
	acceptance *invitesincoming.Acceptance,
) error {
	// Recipient gate first: resolve the recipient-scoped record so a wrong
	// recipient stays ErrInviteNotFound before identity validation runs.
	existing, err := a.s.GetIncomingInviteForRecipient(ctx, id, recipientUserID)
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

	if err := invites.ValidateUpdateAcceptedIdentity(string(status), argUserID, argHost, existing.SenderUserID, existing.SenderFQDNNormalized); err != nil {
		return err
	}

	senderUserID, senderFQDNNormalized := invites.CoalesceAcceptedIdentity(argUserID, argHost, existing.SenderUserID, existing.SenderFQDNNormalized)

	if err := a.s.UpdateIncomingInviteStatusForRecipient(ctx, id, recipientUserID, string(status), senderUserID, senderFQDNNormalized); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return invites.ErrInviteNotFound
		}

		return err
	}

	return nil
}

// FindAcceptedForSender finds an accepted incoming invite for the local
// recipient whose remote sender matches both the given user and normalized
// host. Rows without a persisted normalized sender host never match.
func (a *incomingInviteAdapter) FindAcceptedForSender(
	ctx context.Context,
	recipientUserID string,
	senderUserID string,
	senderFQDNNormalized string,
) (*invitesincoming.IncomingInvite, error) {
	storeInvites, err := a.s.ListIncomingInvites(ctx, recipientUserID)
	if err != nil {
		return nil, err
	}

	for _, s := range storeInvites {
		if s.Status != string(invites.InviteStatusAccepted) || s.SenderUserID != senderUserID {
			continue
		}

		// Rows without a persisted normalized sender host never match, even
		// against an empty query value.
		if s.SenderFQDNNormalized == "" || s.SenderFQDNNormalized != senderFQDNNormalized {
			continue
		}

		return storeIncomingInviteToApp(s), nil
	}

	return nil, invites.ErrInviteNotFound
}

func (a *incomingInviteAdapter) DeleteForRecipientUserID(
	ctx context.Context,
	id string,
	recipientUserID string,
) error {
	if err := a.s.DeleteIncomingInviteForRecipient(ctx, id, recipientUserID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return invites.ErrInviteNotFound
		}

		return err
	}

	return nil
}

// storeIncomingInviteToApp converts a store model to the app-layer model.
func storeIncomingInviteToApp(s *store.IncomingInvite) *invitesincoming.IncomingInvite {
	return &invitesincoming.IncomingInvite{
		ID:              s.ID,
		Token:           s.Token,
		InviteString:    s.InviteString,
		SenderFQDN:      s.SenderFQDN,
		RecipientUserID: s.RecipientUserID,
		Status:          invites.InviteStatus(s.Status),
		ReceivedAt:      unixToTime(s.ReceivedAt),

		SenderUserID:         s.SenderUserID,
		SenderFQDNNormalized: s.SenderFQDNNormalized,
	}
}

// appIncomingInviteToStore converts an app-layer model to the store model.
func appIncomingInviteToStore(a *invitesincoming.IncomingInvite) *store.IncomingInvite {
	return &store.IncomingInvite{
		ID:              a.ID,
		Token:           a.Token,
		InviteString:    a.InviteString,
		SenderFQDN:      a.SenderFQDN,
		RecipientUserID: a.RecipientUserID,
		Status:          string(a.Status),
		ReceivedAt:      timeToUnix(a.ReceivedAt),

		SenderUserID:         a.SenderUserID,
		SenderFQDNNormalized: a.SenderFQDNNormalized,
	}
}
