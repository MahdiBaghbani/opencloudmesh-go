package outgoing

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
)

type OutgoingInviteRepo interface {
	Create(ctx context.Context, invite *OutgoingInvite) error
	GetByID(ctx context.Context, id string) (*OutgoingInvite, error)
	GetByToken(ctx context.Context, token string) (*OutgoingInvite, error)
	List(ctx context.Context) ([]*OutgoingInvite, error)
	UpdateStatus(ctx context.Context, id string, status invites.InviteStatus, acceptedBy string) error
}

type MemoryOutgoingInviteRepo struct {
	mu      sync.RWMutex
	invites map[string]*OutgoingInvite
	byToken map[string]string // token -> id
}

func NewMemoryOutgoingInviteRepo() *MemoryOutgoingInviteRepo {
	return &MemoryOutgoingInviteRepo{
		invites: make(map[string]*OutgoingInvite),
		byToken: make(map[string]string),
	}
}

func (r *MemoryOutgoingInviteRepo) Create(ctx context.Context, invite *OutgoingInvite) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if invite.ID == "" {
		invite.ID = uuid.New().String()
	}
	if invite.CreatedAt.IsZero() {
		invite.CreatedAt = time.Now()
	}
	if invite.Status == "" {
		invite.Status = invites.InviteStatusPending
	}

	r.invites[invite.ID] = invite
	r.byToken[invite.Token] = invite.ID
	return nil
}

func (r *MemoryOutgoingInviteRepo) GetByID(ctx context.Context, id string) (*OutgoingInvite, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	invite, ok := r.invites[id]
	if !ok {
		return nil, invites.ErrInviteNotFound
	}
	return invite, nil
}

func (r *MemoryOutgoingInviteRepo) GetByToken(ctx context.Context, token string) (*OutgoingInvite, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	id, ok := r.byToken[token]
	if !ok {
		return nil, invites.ErrTokenNotFound
	}
	invite, ok := r.invites[id]
	if !ok {
		return nil, invites.ErrInviteNotFound
	}
	return invite, nil
}

func (r *MemoryOutgoingInviteRepo) List(ctx context.Context) ([]*OutgoingInvite, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]*OutgoingInvite, 0, len(r.invites))
	for _, invite := range r.invites {
		result = append(result, invite)
	}
	return result, nil
}

func (r *MemoryOutgoingInviteRepo) UpdateStatus(ctx context.Context, id string, status invites.InviteStatus, acceptedBy string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	invite, ok := r.invites[id]
	if !ok {
		return invites.ErrInviteNotFound
	}
	invite.Status = status
	if acceptedBy != "" {
		invite.AcceptedBy = acceptedBy
		now := time.Now()
		invite.AcceptedAt = &now
	}
	return nil
}
