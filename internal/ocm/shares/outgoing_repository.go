package shares

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// OutgoingShareRepo manages outgoing share storage.
type OutgoingShareRepo interface {
	Create(ctx context.Context, share *OutgoingShare) error
	GetByID(ctx context.Context, shareID string) (*OutgoingShare, error)
	GetByProviderID(ctx context.Context, providerID string) (*OutgoingShare, error)
	GetByWebDAVID(ctx context.Context, webdavID string) (*OutgoingShare, error)
	List(ctx context.Context) ([]*OutgoingShare, error)
	Update(ctx context.Context, share *OutgoingShare) error
}

// MemoryOutgoingShareRepo is an in-memory implementation.
type MemoryOutgoingShareRepo struct {
	mu            sync.RWMutex
	shares        map[string]*OutgoingShare // keyed by shareID
	providerIndex map[string]string         // providerId -> shareID
	webdavIndex   map[string]string         // webdavId -> shareID
}

// NewMemoryOutgoingShareRepo creates a new in-memory repo.
func NewMemoryOutgoingShareRepo() *MemoryOutgoingShareRepo {
	return &MemoryOutgoingShareRepo{
		shares:        make(map[string]*OutgoingShare),
		providerIndex: make(map[string]string),
		webdavIndex:   make(map[string]string),
	}
}

func (r *MemoryOutgoingShareRepo) Create(ctx context.Context, share *OutgoingShare) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if share.ShareID == "" {
		id, _ := uuid.NewV7()
		share.ShareID = id.String()
	}

	share.CreatedAt = time.Now()
	r.shares[share.ShareID] = share
	r.providerIndex[share.ProviderID] = share.ShareID
	r.webdavIndex[share.WebDAVID] = share.ShareID

	return nil
}

func (r *MemoryOutgoingShareRepo) GetByID(ctx context.Context, shareID string) (*OutgoingShare, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	share, ok := r.shares[shareID]
	if !ok {
		return nil, fmt.Errorf("share not found: %s", shareID)
	}
	return share, nil
}

func (r *MemoryOutgoingShareRepo) GetByProviderID(ctx context.Context, providerID string) (*OutgoingShare, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	shareID, ok := r.providerIndex[providerID]
	if !ok {
		return nil, fmt.Errorf("share not found for providerId: %s", providerID)
	}
	return r.shares[shareID], nil
}

func (r *MemoryOutgoingShareRepo) GetByWebDAVID(ctx context.Context, webdavID string) (*OutgoingShare, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	shareID, ok := r.webdavIndex[webdavID]
	if !ok {
		return nil, fmt.Errorf("share not found for webdavId: %s", webdavID)
	}
	return r.shares[shareID], nil
}

func (r *MemoryOutgoingShareRepo) List(ctx context.Context) ([]*OutgoingShare, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]*OutgoingShare, 0, len(r.shares))
	for _, s := range r.shares {
		result = append(result, s)
	}
	return result, nil
}

func (r *MemoryOutgoingShareRepo) Update(ctx context.Context, share *OutgoingShare) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.shares[share.ShareID]; !ok {
		return fmt.Errorf("share not found: %s", share.ShareID)
	}
	r.shares[share.ShareID] = share
	return nil
}
