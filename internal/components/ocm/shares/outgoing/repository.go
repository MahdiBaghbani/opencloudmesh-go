package outgoing

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

type OutgoingShareRepo interface {
	Create(ctx context.Context, share *OutgoingShare) error
	GetByID(ctx context.Context, shareID string) (*OutgoingShare, error)
	GetByProviderID(ctx context.Context, providerID string) (*OutgoingShare, error)
	GetByWebDAVID(ctx context.Context, webdavID string) (*OutgoingShare, error)
	GetBySharedSecret(ctx context.Context, sharedSecret string) (*OutgoingShare, error)
	List(ctx context.Context) ([]*OutgoingShare, error)
	Update(ctx context.Context, share *OutgoingShare) error
}

type MemoryOutgoingShareRepo struct {
	mu            sync.RWMutex
	shares        map[string]*OutgoingShare
	providerIndex map[string]string
	webdavIndex   map[string]string
	secretIndex   map[string]string
}

func NewMemoryOutgoingShareRepo() *MemoryOutgoingShareRepo {
	return &MemoryOutgoingShareRepo{
		shares:        make(map[string]*OutgoingShare),
		providerIndex: make(map[string]string),
		webdavIndex:   make(map[string]string),
		secretIndex:   make(map[string]string),
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
	if share.SharedSecret != "" {
		r.secretIndex[share.SharedSecret] = share.ShareID
	}

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

func (r *MemoryOutgoingShareRepo) GetBySharedSecret(ctx context.Context, sharedSecret string) (*OutgoingShare, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	shareID, ok := r.secretIndex[sharedSecret]
	if !ok {
		return nil, fmt.Errorf("share not found for sharedSecret")
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
