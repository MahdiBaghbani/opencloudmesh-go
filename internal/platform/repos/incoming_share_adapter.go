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

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares"
	sharesincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/incoming"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
)

// incomingShareAdapter adapts store.IncomingShareStore to
// sharesincoming.IncomingShareRepo.
type incomingShareAdapter struct {
	s store.IncomingShareStore
}

var _ sharesincoming.IncomingShareRepo = (*incomingShareAdapter)(nil)

func (a *incomingShareAdapter) Create(ctx context.Context, share *sharesincoming.IncomingShare) error {
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

		return fmt.Errorf("repos: create incoming share: %w", err)
	}

	return nil
}

func (a *incomingShareAdapter) GetByIDForRecipientUserID(
	ctx context.Context,
	shareID string,
	recipientUserID string,
) (*sharesincoming.IncomingShare, error) {
	s, err := a.s.GetIncomingShareByIDForRecipient(ctx, shareID, recipientUserID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, sharesincoming.ErrShareNotFound
		}

		return nil, fmt.Errorf("repos: get incoming share: %w", err)
	}

	return storeIncomingShareToApp(s), nil
}

func (a *incomingShareAdapter) GetByProviderID(
	ctx context.Context,
	senderHost string,
	providerID string,
) (*sharesincoming.IncomingShare, error) {
	s, err := a.s.GetIncomingShareByProviderKey(ctx, senderHost, providerID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, sharesincoming.ErrShareNotFound
		}

		return nil, fmt.Errorf("repos: get incoming share by provider key: %w", err)
	}

	return storeIncomingShareToApp(s), nil
}

func (a *incomingShareAdapter) ListByRecipientUserID(
	ctx context.Context,
	recipientUserID string,
) ([]*sharesincoming.IncomingShare, error) {
	storeShares, err := a.s.ListIncomingSharesByRecipient(ctx, recipientUserID)
	if err != nil {
		return nil, fmt.Errorf("repos: list incoming shares: %w", err)
	}

	result := make([]*sharesincoming.IncomingShare, 0, len(storeShares))
	for _, s := range storeShares {
		result = append(result, storeIncomingShareToApp(s))
	}

	return result, nil
}

func (a *incomingShareAdapter) UpdateStatusForRecipientUserID(
	ctx context.Context,
	shareID string,
	recipientUserID string,
	status shares.ShareStatus,
) error {
	if err := a.s.UpdateIncomingShareStatusForRecipient(ctx, shareID, recipientUserID, string(status)); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return sharesincoming.ErrShareNotFound
		}

		return fmt.Errorf("repos: update incoming share: %w", err)
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
			return sharesincoming.ErrShareNotFound
		}

		return fmt.Errorf("repos: delete incoming share: %w", err)
	}

	return nil
}

// storeIncomingShareToApp converts a store model to the app-layer model.
func storeIncomingShareToApp(s *store.IncomingShare) *sharesincoming.IncomingShare {
	return &sharesincoming.IncomingShare{
		ShareID:           s.ShareID,
		ProviderID:        s.ProviderID,
		SenderHost:        s.SenderHost,
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
		Status:            shares.ShareStatus(s.Status),
		RecipientUserID:   s.RecipientUserID,
		OwnerHost:         s.OwnerHost,
		Requirements:      append([]string(nil), s.Requirements...),
		Expiration:        int64ToInt64Ptr(s.Expiration),
		CreatedAt:         unixToTime(s.CreatedAt),
		UpdatedAt:         unixToTime(s.UpdatedAt),
	}
}

// appIncomingShareToStore converts an app-layer model to the store model.
func appIncomingShareToStore(a *sharesincoming.IncomingShare) *store.IncomingShare {
	return &store.IncomingShare{
		ShareID:           a.ShareID,
		ProviderID:        a.ProviderID,
		SenderHost:        a.SenderHost,
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
		Status:            string(a.Status),
		RecipientUserID:   a.RecipientUserID,
		OwnerHost:         a.OwnerHost,
		Requirements:      append([]string(nil), a.Requirements...),
		Expiration:        int64PtrToInt64(a.Expiration),
		CreatedAt:         timeToUnix(a.CreatedAt),
		UpdatedAt:         timeToUnix(a.UpdatedAt),
	}
}
