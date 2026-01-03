package shares

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// IncomingShareRepo manages incoming share storage.
type IncomingShareRepo interface {
	// Create stores a new incoming share.
	Create(ctx context.Context, share *IncomingShare) error

	// GetByID retrieves a share by local share ID.
	GetByID(ctx context.Context, shareID string) (*IncomingShare, error)

	// GetByProviderID retrieves a share by sender-scoped providerId.
	GetByProviderID(ctx context.Context, senderHost, providerID string) (*IncomingShare, error)

	// ListByUser retrieves all shares for a recipient user.
	ListByUser(ctx context.Context, shareWith string) ([]*IncomingShare, error)

	// UpdateStatus updates the acceptance status of a share.
	UpdateStatus(ctx context.Context, shareID string, status ShareStatus) error

	// Delete removes a share.
	Delete(ctx context.Context, shareID string) error
}

// MemoryIncomingShareRepo is an in-memory implementation of IncomingShareRepo.
type MemoryIncomingShareRepo struct {
	mu     sync.RWMutex
	shares map[string]*IncomingShare // keyed by shareID

	// Index for sender-scoped providerId lookup
	providerIndex map[string]string // "senderHost:providerId" -> shareID
}

// NewMemoryIncomingShareRepo creates a new in-memory share repository.
func NewMemoryIncomingShareRepo() *MemoryIncomingShareRepo {
	return &MemoryIncomingShareRepo{
		shares:        make(map[string]*IncomingShare),
		providerIndex: make(map[string]string),
	}
}

// generateUUIDv7 generates a UUIDv7 for share IDs.
func generateUUIDv7() string {
	// uuid.NewV7 returns a time-ordered UUID
	id, err := uuid.NewV7()
	if err != nil {
		// Fallback to V4 if V7 fails
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

	// Generate share ID if not set
	if share.ShareID == "" {
		share.ShareID = generateUUIDv7()
	}

	// Check for duplicate providerId from same sender
	key := incomingProviderKey(share.SenderHost, share.ProviderID)
	if _, exists := r.providerIndex[key]; exists {
		return fmt.Errorf("share with providerId %s from sender %s already exists", share.ProviderID, share.SenderHost)
	}

	// Set timestamps
	now := time.Now()
	share.CreatedAt = now
	share.UpdatedAt = now

	// Store
	r.shares[share.ShareID] = share
	r.providerIndex[key] = share.ShareID

	return nil
}

func (r *MemoryIncomingShareRepo) GetByID(ctx context.Context, shareID string) (*IncomingShare, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	share, exists := r.shares[shareID]
	if !exists {
		return nil, fmt.Errorf("share not found: %s", shareID)
	}

	return share, nil
}

func (r *MemoryIncomingShareRepo) GetByProviderID(ctx context.Context, senderHost, providerID string) (*IncomingShare, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	key := incomingProviderKey(senderHost, providerID)
	shareID, exists := r.providerIndex[key]
	if !exists {
		return nil, fmt.Errorf("share not found for providerId %s from sender %s", providerID, senderHost)
	}

	return r.shares[shareID], nil
}

func (r *MemoryIncomingShareRepo) ListByUser(ctx context.Context, shareWith string) ([]*IncomingShare, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []*IncomingShare
	for _, share := range r.shares {
		if share.ShareWith == shareWith {
			result = append(result, share)
		}
	}

	return result, nil
}

func (r *MemoryIncomingShareRepo) UpdateStatus(ctx context.Context, shareID string, status ShareStatus) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	share, exists := r.shares[shareID]
	if !exists {
		return fmt.Errorf("share not found: %s", shareID)
	}

	share.Status = status
	share.UpdatedAt = time.Now()

	return nil
}

func (r *MemoryIncomingShareRepo) Delete(ctx context.Context, shareID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	share, exists := r.shares[shareID]
	if !exists {
		return fmt.Errorf("share not found: %s", shareID)
	}

	// Remove from index
	key := incomingProviderKey(share.SenderHost, share.ProviderID)
	delete(r.providerIndex, key)

	// Remove share
	delete(r.shares, shareID)

	return nil
}
