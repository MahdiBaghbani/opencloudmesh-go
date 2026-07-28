package repos

import (
	"context"
	"errors"
	"fmt"
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

	s := appOutgoingInviteToStore(invite)
	if err := a.s.CreateOutgoingInvite(ctx, s); err != nil {
		if errors.Is(err, store.ErrAlreadyExists) {
			return fmt.Errorf("invite already exists: %s", invite.ID)
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
	acceptedBy string,
) error {
	existing, err := a.s.GetOutgoingInvite(ctx, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return invites.ErrInviteNotFound
		}

		return err
	}

	existing.Status = string(status)
	if acceptedBy != "" {
		existing.AcceptedBy = acceptedBy
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
		AcceptedBy:      s.AcceptedBy,
		AcceptedAt:      unixToTimePtr(s.AcceptedAt),
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
		AcceptedBy:      a.AcceptedBy,
		ExpiresAt:       timeToUnix(a.ExpiresAt),
		CreatedAt:       timeToUnix(a.CreatedAt),
		AcceptedAt:      timePtrToUnix(a.AcceptedAt),
	}
}
