package repos

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
	invitesinbox "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/inbox"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
)

// incomingInviteAdapter adapts store.IncomingInviteStore to
// invitesinbox.IncomingInviteRepo.
type incomingInviteAdapter struct {
	s store.IncomingInviteStore
}

var _ invitesinbox.IncomingInviteRepo = (*incomingInviteAdapter)(nil)

func (a *incomingInviteAdapter) Create(ctx context.Context, invite *invitesinbox.IncomingInvite) error {
	if invite.ID == "" {
		invite.ID = uuid.New().String()
	}

	if invite.ReceivedAt.IsZero() {
		invite.ReceivedAt = time.Now()
	}

	if invite.Status == "" {
		invite.Status = invites.InviteStatusPending
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
) (*invitesinbox.IncomingInvite, error) {
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
) (*invitesinbox.IncomingInvite, error) {
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
) ([]*invitesinbox.IncomingInvite, error) {
	storeInvites, err := a.s.ListIncomingInvites(ctx, recipientUserID)
	if err != nil {
		return nil, err
	}

	result := make([]*invitesinbox.IncomingInvite, 0, len(storeInvites))
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
) error {
	if err := a.s.UpdateIncomingInviteStatusForRecipient(ctx, id, recipientUserID, string(status)); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return invites.ErrInviteNotFound
		}

		return err
	}

	return nil
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
func storeIncomingInviteToApp(s *store.IncomingInvite) *invitesinbox.IncomingInvite {
	return &invitesinbox.IncomingInvite{
		ID:              s.ID,
		Token:           s.Token,
		InviteString:    s.InviteString,
		SenderFQDN:      s.SenderFQDN,
		RecipientUserID: s.RecipientUserID,
		Status:          invites.InviteStatus(s.Status),
		ReceivedAt:      unixToTime(s.ReceivedAt),
	}
}

// appIncomingInviteToStore converts an app-layer model to the store model.
func appIncomingInviteToStore(a *invitesinbox.IncomingInvite) *store.IncomingInvite {
	return &store.IncomingInvite{
		ID:              a.ID,
		Token:           a.Token,
		InviteString:    a.InviteString,
		SenderFQDN:      a.SenderFQDN,
		RecipientUserID: a.RecipientUserID,
		Status:          string(a.Status),
		ReceivedAt:      timeToUnix(a.ReceivedAt),
	}
}
