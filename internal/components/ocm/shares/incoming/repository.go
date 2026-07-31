// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package incoming

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares"
)

// ErrShareNotFound is returned when a share is not found (including cross-user mismatch).
var ErrShareNotFound = errors.New("share not found")

// IncomingShareRepo manages incoming shares; all ops scoped by recipientUserID. Cross-user access = not found.
type IncomingShareRepo interface {
	Create(ctx context.Context, share *IncomingShare) error
	GetByIDForRecipientUserID(ctx context.Context, shareID string, recipientUserID string) (*IncomingShare, error)
	GetByProviderID(ctx context.Context, senderHost, providerID string) (*IncomingShare, error)
	ListByRecipientUserID(ctx context.Context, recipientUserID string) ([]*IncomingShare, error)
	UpdateStatusForRecipientUserID(ctx context.Context, shareID string, recipientUserID string, status shares.ShareStatus) error
	DeleteForRecipientUserID(ctx context.Context, shareID string, recipientUserID string) error
}

// MemoryIncomingShareRepo stores incoming shares in memory, scoped by recipient user id; implements IncomingShareRepo.
type MemoryIncomingShareRepo struct {
	mu                sync.RWMutex
	shares            map[string]*IncomingShare
	providerIndex     map[string]string
	byRecipientUserID map[string]map[string]struct{}
}

func NewMemoryIncomingShareRepo() *MemoryIncomingShareRepo { //nolint:revive // exported: trivial constructor initializing the in-memory share maps
	return &MemoryIncomingShareRepo{
		shares:            make(map[string]*IncomingShare),
		providerIndex:     make(map[string]string),
		byRecipientUserID: make(map[string]map[string]struct{}),
	}
}

func generateUUIDv7() string {
	id, err := uuid.NewV7()
	if err != nil {
		return uuid.New().String()
	}

	return id.String()
}

func incomingProviderKey(senderHost, providerID string) string {
	return fmt.Sprintf("%s:%s", senderHost, providerID)
}

// Create stores the share, assigning ShareID and timestamps; implements IncomingShareRepo.
func (r *MemoryIncomingShareRepo) Create(_ context.Context, share *IncomingShare) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if share.ShareID == "" {
		share.ShareID = generateUUIDv7()
	}

	key := incomingProviderKey(share.SenderHost, share.ProviderID)
	if _, exists := r.providerIndex[key]; exists {
		return fmt.Errorf("share with providerId %s from sender %s already exists", share.ProviderID, share.SenderHost)
	}

	now := time.Now()
	share.CreatedAt = now
	share.UpdatedAt = now

	r.shares[share.ShareID] = share

	r.providerIndex[key] = share.ShareID
	if share.RecipientUserID != "" {
		if r.byRecipientUserID[share.RecipientUserID] == nil {
			r.byRecipientUserID[share.RecipientUserID] = make(map[string]struct{})
		}

		r.byRecipientUserID[share.RecipientUserID][share.ShareID] = struct{}{}
	}

	return nil
}

// GetByIDForRecipientUserID returns the share when its recipient matches; implements IncomingShareRepo.
func (r *MemoryIncomingShareRepo) GetByIDForRecipientUserID(_ context.Context, shareID string, recipientUserID string) (*IncomingShare, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	share, exists := r.shares[shareID]
	if !exists || share.RecipientUserID != recipientUserID {
		return nil, ErrShareNotFound
	}

	return share, nil
}

// GetByProviderID returns the share indexed by sender host and providerID; implements IncomingShareRepo.
func (r *MemoryIncomingShareRepo) GetByProviderID(_ context.Context, senderHost, providerID string) (*IncomingShare, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	key := incomingProviderKey(senderHost, providerID)

	shareID, exists := r.providerIndex[key]
	if !exists {
		return nil, ErrShareNotFound
	}

	return r.shares[shareID], nil
}

// ListByRecipientUserID returns all shares for the given recipient; implements IncomingShareRepo.
func (r *MemoryIncomingShareRepo) ListByRecipientUserID(_ context.Context, recipientUserID string) ([]*IncomingShare, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	ids, exists := r.byRecipientUserID[recipientUserID]
	if !exists {
		return nil, nil
	}

	result := make([]*IncomingShare, 0, len(ids))
	for id := range ids {
		if share, ok := r.shares[id]; ok {
			result = append(result, share)
		}
	}

	return result, nil
}

// UpdateStatusForRecipientUserID sets the share status when the recipient matches; implements IncomingShareRepo.
func (r *MemoryIncomingShareRepo) UpdateStatusForRecipientUserID(_ context.Context, shareID string, recipientUserID string, status shares.ShareStatus) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	share, exists := r.shares[shareID]
	if !exists || share.RecipientUserID != recipientUserID {
		return ErrShareNotFound
	}

	share.Status = status
	share.UpdatedAt = time.Now()

	return nil
}

// DeleteForRecipientUserID removes the share and its indexes when the recipient matches; implements IncomingShareRepo.
func (r *MemoryIncomingShareRepo) DeleteForRecipientUserID(_ context.Context, shareID string, recipientUserID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	share, exists := r.shares[shareID]
	if !exists || share.RecipientUserID != recipientUserID {
		return ErrShareNotFound
	}

	key := incomingProviderKey(share.SenderHost, share.ProviderID)
	delete(r.providerIndex, key)

	if ids, ok := r.byRecipientUserID[share.RecipientUserID]; ok {
		delete(ids, shareID)

		if len(ids) == 0 {
			delete(r.byRecipientUserID, share.RecipientUserID)
		}
	}

	delete(r.shares, shareID)

	return nil
}
