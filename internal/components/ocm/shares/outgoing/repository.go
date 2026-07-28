package outgoing

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

type OutgoingShareRepo interface { //nolint:revive // exported: self-explanatory CRUD interface for outgoing shares
	Create(ctx context.Context, share *OutgoingShare) error
	GetByID(ctx context.Context, shareID string) (*OutgoingShare, error)
	GetByProviderID(ctx context.Context, providerID string) (*OutgoingShare, error)
	GetByWebDAVID(ctx context.Context, webdavID string) (*OutgoingShare, error)
	GetBySharedSecret(ctx context.Context, sharedSecret string) (*OutgoingShare, error)
	List(ctx context.Context) ([]*OutgoingShare, error)
	Update(ctx context.Context, share *OutgoingShare) error
}

// MemoryOutgoingShareRepo stores outgoing shares in memory; implements OutgoingShareRepo.
type MemoryOutgoingShareRepo struct {
	mu            sync.RWMutex
	shares        map[string]*OutgoingShare
	providerIndex map[string]string
	webdavIndex   map[string]string
	secretIndex   map[string]string
}

func NewMemoryOutgoingShareRepo() *MemoryOutgoingShareRepo { //nolint:revive // exported: trivial constructor initializing the in-memory share maps
	return &MemoryOutgoingShareRepo{
		shares:        make(map[string]*OutgoingShare),
		providerIndex: make(map[string]string),
		webdavIndex:   make(map[string]string),
		secretIndex:   make(map[string]string),
	}
}

// Create stores the share, assigning ShareID and indexes; implements OutgoingShareRepo.
func (r *MemoryOutgoingShareRepo) Create(_ context.Context, share *OutgoingShare) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if share.ShareID == "" {
		id, err := uuid.NewV7()
		if err != nil {
			return fmt.Errorf("generate share id: %w", err)
		}

		share.ShareID = id.String()
	}

	share.CreatedAt = time.Now()
	r.shares[share.ShareID] = share
	r.providerIndex[share.ProviderID] = share.ShareID

	r.webdavIndex[share.WebDAVID] = share.ShareID
	if share.SharedSecret != "" {
		r.secretIndex[share.SharedSecret] = share.ShareID
	}

	return nil
}

// GetByID returns the share with the given id; implements OutgoingShareRepo.
func (r *MemoryOutgoingShareRepo) GetByID(_ context.Context, shareID string) (*OutgoingShare, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	share, ok := r.shares[shareID]
	if !ok {
		return nil, fmt.Errorf("share not found: %s", shareID)
	}

	return share, nil
}

// GetByProviderID returns the share indexed by providerID; implements OutgoingShareRepo.
func (r *MemoryOutgoingShareRepo) GetByProviderID(_ context.Context, providerID string) (*OutgoingShare, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	shareID, ok := r.providerIndex[providerID]
	if !ok {
		return nil, fmt.Errorf("share not found for providerId: %s", providerID)
	}

	return r.shares[shareID], nil
}

// GetByWebDAVID returns the share indexed by webdavId; implements OutgoingShareRepo.
func (r *MemoryOutgoingShareRepo) GetByWebDAVID(_ context.Context, webdavID string) (*OutgoingShare, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	shareID, ok := r.webdavIndex[webdavID]
	if !ok {
		return nil, fmt.Errorf("share not found for webdavId: %s", webdavID)
	}

	return r.shares[shareID], nil
}

// GetBySharedSecret returns the share indexed by sharedSecret; implements OutgoingShareRepo.
func (r *MemoryOutgoingShareRepo) GetBySharedSecret(_ context.Context, sharedSecret string) (*OutgoingShare, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	shareID, ok := r.secretIndex[sharedSecret]
	if !ok {
		return nil, fmt.Errorf("share not found for sharedSecret")
	}

	return r.shares[shareID], nil
}

// List returns all stored shares; implements OutgoingShareRepo.
func (r *MemoryOutgoingShareRepo) List(_ context.Context) ([]*OutgoingShare, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]*OutgoingShare, 0, len(r.shares))
	for _, s := range r.shares {
		result = append(result, s)
	}

	return result, nil
}

// Update replaces the stored share by ShareID; implements OutgoingShareRepo.
func (r *MemoryOutgoingShareRepo) Update(_ context.Context, share *OutgoingShare) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.shares[share.ShareID]; !ok {
		return fmt.Errorf("share not found: %s", share.ShareID)
	}

	r.shares[share.ShareID] = share

	return nil
}
