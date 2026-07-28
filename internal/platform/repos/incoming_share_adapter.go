package repos

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	sharesinbox "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/inbox"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
)

// incomingShareAdapter adapts store.IncomingShareStore to
// sharesinbox.IncomingShareRepo.
type incomingShareAdapter struct {
	s store.IncomingShareStore
}

var _ sharesinbox.IncomingShareRepo = (*incomingShareAdapter)(nil)

func (a *incomingShareAdapter) Create(ctx context.Context, share *sharesinbox.IncomingShare) error {
	if share.ShareID == "" {
		id, err := uuid.NewV7()
		if err != nil {
			share.ShareID = uuid.New().String()
		} else {
			share.ShareID = id.String()
		}
	}

	now := time.Now()
	if share.CreatedAt.IsZero() {
		share.CreatedAt = now
	}

	if share.UpdatedAt.IsZero() {
		share.UpdatedAt = now
	}

	s := appIncomingShareToStore(share)
	if err := a.s.CreateIncomingShare(ctx, s); err != nil {
		if errors.Is(err, store.ErrAlreadyExists) {
			return fmt.Errorf("share already exists: %w", store.ErrAlreadyExists)
		}

		return err
	}

	return nil
}

func (a *incomingShareAdapter) GetByIDForRecipientUserID(
	ctx context.Context,
	shareID string,
	recipientUserID string,
) (*sharesinbox.IncomingShare, error) {
	s, err := a.s.GetIncomingShareByIDForRecipient(ctx, shareID, recipientUserID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, sharesinbox.ErrShareNotFound
		}

		return nil, err
	}

	return storeIncomingShareToApp(s), nil
}

func (a *incomingShareAdapter) GetByProviderID(
	ctx context.Context,
	senderHost string,
	providerID string,
) (*sharesinbox.IncomingShare, error) {
	s, err := a.s.GetIncomingShareByProviderKey(ctx, senderHost, providerID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, sharesinbox.ErrShareNotFound
		}

		return nil, err
	}

	return storeIncomingShareToApp(s), nil
}

func (a *incomingShareAdapter) ListByRecipientUserID(
	ctx context.Context,
	recipientUserID string,
) ([]*sharesinbox.IncomingShare, error) {
	storeShares, err := a.s.ListIncomingSharesByRecipient(ctx, recipientUserID)
	if err != nil {
		return nil, err
	}

	result := make([]*sharesinbox.IncomingShare, 0, len(storeShares))
	for _, s := range storeShares {
		result = append(result, storeIncomingShareToApp(s))
	}

	return result, nil
}

func (a *incomingShareAdapter) UpdateStatusForRecipientUserID(
	ctx context.Context,
	shareID string,
	recipientUserID string,
	status sharesinbox.ShareStatus,
) error {
	if err := a.s.UpdateIncomingShareStatusForRecipient(ctx, shareID, recipientUserID, string(status)); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return sharesinbox.ErrShareNotFound
		}

		return err
	}

	return nil
}

func (a *incomingShareAdapter) DeleteForRecipientUserID(
	ctx context.Context,
	shareID string,
	recipientUserID string,
) error {
	if err := a.s.DeleteIncomingShareForRecipient(ctx, shareID, recipientUserID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return sharesinbox.ErrShareNotFound
		}

		return err
	}

	return nil
}

// storeIncomingShareToApp converts a store model to the app-layer model.
func storeIncomingShareToApp(s *store.IncomingShare) *sharesinbox.IncomingShare {
	return &sharesinbox.IncomingShare{
		ShareID:           s.ShareID,
		ProviderID:        s.ProviderID,
		SenderHost:        s.SendingServer,
		WebDAVID:          s.WebDAVID,
		SharedSecret:      s.SharedSecret,
		Owner:             s.Owner,
		Sender:            s.Sender,
		ShareWith:         s.ShareWith,
		Name:              s.Name,
		Description:       s.Description,
		ResourceType:      s.ResourceType,
		ShareType:         s.ShareType,
		OwnerDisplayName:  s.OwnerDisplayName,
		SenderDisplayName: s.SenderDisplayName,
		Permissions:       permStringToSlice(s.Permissions),
		WebappPermissions: permStringToSlice(s.WebappPermissions),
		WebappURI:         s.WebappURI,
		WebappTargets:     append([]string(nil), s.WebappTargets...),
		ProtocolName:      s.ProtocolName,
		Status:            sharesinbox.ShareStatus(s.State),
		RecipientUserID:   s.UserID,
		OwnerHost:         s.OwnerHost,
		Requirements:      append([]string(nil), s.Requirements...),
		Expiration:        int64ToInt64Ptr(s.Expiration),
		CreatedAt:         unixToTime(s.CreatedAt),
		UpdatedAt:         unixToTime(s.UpdatedAt),
	}
}

// appIncomingShareToStore converts an app-layer model to the store model.
func appIncomingShareToStore(a *sharesinbox.IncomingShare) *store.IncomingShare {
	return &store.IncomingShare{
		ShareID:           a.ShareID,
		ProviderID:        a.ProviderID,
		SendingServer:     a.SenderHost,
		WebDAVID:          a.WebDAVID,
		SharedSecret:      a.SharedSecret,
		Owner:             a.Owner,
		Sender:            a.Sender,
		ShareWith:         a.ShareWith,
		Name:              a.Name,
		Description:       a.Description,
		ResourceType:      a.ResourceType,
		ShareType:         a.ShareType,
		OwnerDisplayName:  a.OwnerDisplayName,
		SenderDisplayName: a.SenderDisplayName,
		Permissions:       permSliceToString(a.Permissions),
		WebappPermissions: permSliceToString(a.WebappPermissions),
		WebappURI:         a.WebappURI,
		WebappTargets:     append([]string(nil), a.WebappTargets...),
		ProtocolName:      a.ProtocolName,
		State:             string(a.Status),
		UserID:            a.RecipientUserID,
		OwnerHost:         a.OwnerHost,
		Requirements:      append([]string(nil), a.Requirements...),
		Expiration:        int64PtrToInt64(a.Expiration),
		CreatedAt:         timeToUnix(a.CreatedAt),
		UpdatedAt:         timeToUnix(a.UpdatedAt),
	}
}
