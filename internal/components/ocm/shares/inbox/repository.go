package inbox

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// ErrShareNotFound is returned when a share is not found (including cross-user mismatch).
var ErrShareNotFound = errors.New("share not found")

// IncomingShareRepo manages incoming shares; all ops scoped by recipientUserID. Cross-user access = not found.
type IncomingShareRepo interface {
	Create(ctx context.Context, share *IncomingShare) error
	GetByIDForRecipientUserID(ctx context.Context, shareID string, recipientUserID string) (*IncomingShare, error)
	GetByProviderID(ctx context.Context, senderHost, providerID string) (*IncomingShare, error)
	ListByRecipientUserID(ctx context.Context, recipientUserID string) ([]*IncomingShare, error)
	UpdateStatusForRecipientUserID(ctx context.Context, shareID string, recipientUserID string, status ShareStatus) error
	DeleteForRecipientUserID(ctx context.Context, shareID string, recipientUserID string) error
}

type MemoryIncomingShareRepo struct {
	mu               sync.RWMutex
	shares           map[string]*IncomingShare
	providerIndex    map[string]string
	byRecipientUserID map[string]map[string]struct{}
}

func NewMemoryIncomingShareRepo() *MemoryIncomingShareRepo {
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

func (r *MemoryIncomingShareRepo) Create(ctx context.Context, share *IncomingShare) error {
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

func (r *MemoryIncomingShareRepo) GetByIDForRecipientUserID(ctx context.Context, shareID string, recipientUserID string) (*IncomingShare, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	share, exists := r.shares[shareID]
	if !exists || share.RecipientUserID != recipientUserID {
		return nil, ErrShareNotFound
	}

	return share, nil
}

func (r *MemoryIncomingShareRepo) GetByProviderID(ctx context.Context, senderHost, providerID string) (*IncomingShare, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	key := incomingProviderKey(senderHost, providerID)
	shareID, exists := r.providerIndex[key]
	if !exists {
		return nil, ErrShareNotFound
	}

	return r.shares[shareID], nil
}

func (r *MemoryIncomingShareRepo) ListByRecipientUserID(ctx context.Context, recipientUserID string) ([]*IncomingShare, error) {
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

func (r *MemoryIncomingShareRepo) UpdateStatusForRecipientUserID(ctx context.Context, shareID string, recipientUserID string, status ShareStatus) error {
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

func (r *MemoryIncomingShareRepo) DeleteForRecipientUserID(ctx context.Context, shareID string, recipientUserID string) error {
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
