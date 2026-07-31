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
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
)

// outgoingShareAdapter adapts store.OutgoingShareStore to
// sharesoutgoing.OutgoingShareRepo.
type outgoingShareAdapter struct {
	s store.OutgoingShareStore
}

var _ sharesoutgoing.OutgoingShareRepo = (*outgoingShareAdapter)(nil)

func (a *outgoingShareAdapter) Create(ctx context.Context, share *sharesoutgoing.OutgoingShare) error {
	if share.ShareID == "" {
		id, err := uuid.NewV7()
		if err != nil {
			return fmt.Errorf("generate share id: %w", err)
		}

		share.ShareID = id.String()
	}

	if share.CreatedAt.IsZero() {
		share.CreatedAt = time.Now()
	}

	s := appOutgoingShareToStore(share)
	if err := a.s.CreateOutgoingShare(ctx, s); err != nil {
		if errors.Is(err, store.ErrAlreadyExists) {
			return fmt.Errorf("share already exists: %s", share.ShareID)
		}

		return err
	}

	return nil
}

func (a *outgoingShareAdapter) GetByID(ctx context.Context, shareID string) (*sharesoutgoing.OutgoingShare, error) {
	s, err := a.s.GetOutgoingShareByID(ctx, shareID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, fmt.Errorf("share not found: %s", shareID)
		}

		return nil, err
	}

	return storeOutgoingShareToApp(s), nil
}

func (a *outgoingShareAdapter) GetByProviderID(ctx context.Context, providerID string) (*sharesoutgoing.OutgoingShare, error) {
	s, err := a.s.GetOutgoingShare(ctx, providerID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, fmt.Errorf("share not found for providerId: %s", providerID)
		}

		return nil, err
	}

	return storeOutgoingShareToApp(s), nil
}

func (a *outgoingShareAdapter) GetByWebDAVID(ctx context.Context, webdavID string) (*sharesoutgoing.OutgoingShare, error) {
	s, err := a.s.GetOutgoingShareByWebDAVID(ctx, webdavID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, fmt.Errorf("share not found for webdavId: %s", webdavID)
		}

		return nil, err
	}

	return storeOutgoingShareToApp(s), nil
}

func (a *outgoingShareAdapter) GetBySharedSecret(ctx context.Context, sharedSecret string) (*sharesoutgoing.OutgoingShare, error) {
	s, err := a.s.GetOutgoingShareBySharedSecret(ctx, sharedSecret)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, fmt.Errorf("share not found for sharedSecret")
		}

		return nil, err
	}

	return storeOutgoingShareToApp(s), nil
}

func (a *outgoingShareAdapter) List(ctx context.Context) ([]*sharesoutgoing.OutgoingShare, error) {
	storeShares, err := a.s.ListOutgoingShares(ctx)
	if err != nil {
		return nil, err
	}

	result := make([]*sharesoutgoing.OutgoingShare, 0, len(storeShares))
	for _, s := range storeShares {
		result = append(result, storeOutgoingShareToApp(s))
	}

	return result, nil
}

func (a *outgoingShareAdapter) Update(ctx context.Context, share *sharesoutgoing.OutgoingShare) error {
	s := appOutgoingShareToStore(share)
	if err := a.s.UpdateOutgoingShare(ctx, s); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("share not found: %s", share.ShareID)
		}

		return err
	}

	return nil
}

// storeOutgoingShareToApp converts a store model to the app-layer model.
// UpdatedAt in the store carries SentAt semantics for outgoing shares;
// the write path maps SentAt -> UpdatedAt, so the read path reverses that.
func storeOutgoingShareToApp(s *store.OutgoingShare) *sharesoutgoing.OutgoingShare {
	return &sharesoutgoing.OutgoingShare{
		ShareID:          s.ShareID,
		ProviderID:       s.ProviderID,
		WebDAVID:         s.WebDAVID,
		SharedSecret:     s.SharedSecret,
		LocalPath:        s.LocalPath,
		ReceiverHost:     s.ReceiverHost,
		ReceiverEndPoint: s.ReceiverEndPoint,
		ShareWith:        s.ShareWith,
		Name:             s.Name,
		ResourceType:     s.ResourceType,
		ShareType:        s.ShareType,
		Permissions:      permStringToSlice(s.Permissions),
		Owner:            s.Owner,
		Sender:           s.Sender,
		Status:           shares.OutgoingShareStatus(s.Status),
		Error:            s.Error,
		// Copy the slice so callers cannot mutate the store's backing array.
		Requirements: append([]string(nil), s.Requirements...),
		CreatedAt:    unixToTime(s.CreatedAt),
		SentAt:       unixToTimePtr(s.UpdatedAt),
	}
}

// appOutgoingShareToStore converts an app-layer model to the store model.
func appOutgoingShareToStore(a *sharesoutgoing.OutgoingShare) *store.OutgoingShare {
	return &store.OutgoingShare{
		ShareID:          a.ShareID,
		ProviderID:       a.ProviderID,
		WebDAVID:         a.WebDAVID,
		SharedSecret:     a.SharedSecret,
		LocalPath:        a.LocalPath,
		ReceiverHost:     a.ReceiverHost,
		ReceiverEndPoint: a.ReceiverEndPoint,
		ShareWith:        a.ShareWith,
		Name:             a.Name,
		ResourceType:     a.ResourceType,
		ShareType:        a.ShareType,
		Permissions:      permSliceToString(a.Permissions),
		Owner:            a.Owner,
		Sender:           a.Sender,
		Status:           string(a.Status),
		Error:            a.Error,
		// Copy the slice so the store cannot mutate the caller's backing array.
		Requirements: append([]string(nil), a.Requirements...),
		CreatedAt:    timeToUnix(a.CreatedAt),
		UpdatedAt:    timePtrToUnix(a.SentAt),
	}
}
