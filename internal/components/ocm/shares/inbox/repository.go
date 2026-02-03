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

// IncomingShareRepo manages incoming share storage.
// All lookup and mutation methods are scoped by recipientUserID.
// Cross-user access behaves as not found (confidentiality invariant).
type IncomingShareRepo interface {
	// Create stores a new incoming share.
	Create(ctx context.Context, share *IncomingShare) error

	// GetByIDForRecipientUserID retrieves a share scoped to a specific recipient.
	// Returns ErrShareNotFound if the share does not exist or belongs to another user.
	GetByIDForRecipientUserID(ctx context.Context, shareID string, recipientUserID string) (*IncomingShare, error)

	// GetByProviderID retrieves a share by sender-scoped providerId (unscoped, for duplicate detection).
	GetByProviderID(ctx context.Context, senderHost, providerID string) (*IncomingShare, error)

	// ListByRecipientUserID retrieves all shares owned by a specific recipient.
	ListByRecipientUserID(ctx context.Context, recipientUserID string) ([]*IncomingShare, error)

	// UpdateStatusForRecipientUserID updates acceptance status, scoped by recipient.
	// Returns ErrShareNotFound if the share does not exist or belongs to another user.
	UpdateStatusForRecipientUserID(ctx context.Context, shareID string, recipientUserID string, status ShareStatus) error

	// DeleteForRecipientUserID removes a share, scoped by recipient.
	// Returns ErrShareNotFound if the share does not exist or belongs to another user.
	DeleteForRecipientUserID(ctx context.Context, shareID string, recipientUserID string) error
}

// MemoryIncomingShareRepo is an in-memory implementation of IncomingShareRepo.
type MemoryIncomingShareRepo struct {
	mu     sync.RWMutex
	shares map[string]*IncomingShare // keyed by shareID

	// Index for sender-scoped providerId lookup (duplicate detection)
	providerIndex map[string]string // "senderHost:providerId" -> shareID

	// Index for per-user listing
	byRecipientUserID map[string]map[string]struct{} // recipientUserID -> set of shareIDs
}

// NewMemoryIncomingShareRepo creates a new in-memory share repository.
func NewMemoryIncomingShareRepo() *MemoryIncomingShareRepo {
	return &MemoryIncomingShareRepo{
		shares:            make(map[string]*IncomingShare),
		providerIndex:     make(map[string]string),
		byRecipientUserID: make(map[string]map[string]struct{}),
	}
}

// generateUUIDv7 generates a UUIDv7 for share IDs.
func generateUUIDv7() string {
	id, err := uuid.NewV7()
	if err != nil {
		return uuid.New().String()
	}
	return id.String()
}

// incomingProviderKey creates the sender-scoped lookup key.
func incomingProviderKey(senderHost, providerID string) string {
	return fmt.Sprintf("%s:%s", senderHost, providerID)
}

func (r *MemoryIncomingShareRepo) Create(ctx context.Context, share *IncomingShare) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if share.ShareID == "" {
		share.ShareID = generateUUIDv7()
	}

	// Check for duplicate providerId from same sender
	key := incomingProviderKey(share.SenderHost, share.ProviderID)
	if _, exists := r.providerIndex[key]; exists {
		return fmt.Errorf("share with providerId %s from sender %s already exists", share.ProviderID, share.SenderHost)
	}

	now := time.Now()
	share.CreatedAt = now
	share.UpdatedAt = now

	r.shares[share.ShareID] = share
	r.providerIndex[key] = share.ShareID

	// Maintain byRecipientUserID index
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

	// Remove from indexes
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
