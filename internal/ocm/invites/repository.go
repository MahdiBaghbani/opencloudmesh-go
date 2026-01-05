package invites

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
)

var (
	ErrInviteNotFound = errors.New("invite not found")
	ErrTokenNotFound  = errors.New("token not found")
)

// OutgoingInviteRepo manages outgoing invites.
type OutgoingInviteRepo interface {
	Create(ctx context.Context, invite *OutgoingInvite) error
	GetByID(ctx context.Context, id string) (*OutgoingInvite, error)
	GetByToken(ctx context.Context, token string) (*OutgoingInvite, error)
	List(ctx context.Context) ([]*OutgoingInvite, error)
	UpdateStatus(ctx context.Context, id string, status InviteStatus, acceptedBy string) error
}

// IncomingInviteRepo manages incoming invites.
type IncomingInviteRepo interface {
	Create(ctx context.Context, invite *IncomingInvite) error
	GetByID(ctx context.Context, id string) (*IncomingInvite, error)
	List(ctx context.Context) ([]*IncomingInvite, error)
	UpdateStatus(ctx context.Context, id string, status InviteStatus) error
	Delete(ctx context.Context, id string) error
}

// MemoryOutgoingInviteRepo is an in-memory implementation.
type MemoryOutgoingInviteRepo struct {
	mu      sync.RWMutex
	invites map[string]*OutgoingInvite
	byToken map[string]string // token -> id
}

// NewMemoryOutgoingInviteRepo creates a new in-memory outgoing invite repo.
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
		invite.Status = InviteStatusPending
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
		return nil, ErrInviteNotFound
	}
	return invite, nil
}

func (r *MemoryOutgoingInviteRepo) GetByToken(ctx context.Context, token string) (*OutgoingInvite, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	id, ok := r.byToken[token]
	if !ok {
		return nil, ErrTokenNotFound
	}
	invite, ok := r.invites[id]
	if !ok {
		return nil, ErrInviteNotFound
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

func (r *MemoryOutgoingInviteRepo) UpdateStatus(ctx context.Context, id string, status InviteStatus, acceptedBy string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	invite, ok := r.invites[id]
	if !ok {
		return ErrInviteNotFound
	}
	invite.Status = status
	if acceptedBy != "" {
		invite.AcceptedBy = acceptedBy
		now := time.Now()
		invite.AcceptedAt = &now
	}
	return nil
}

// MemoryIncomingInviteRepo is an in-memory implementation.
type MemoryIncomingInviteRepo struct {
	mu      sync.RWMutex
	invites map[string]*IncomingInvite
}

// NewMemoryIncomingInviteRepo creates a new in-memory incoming invite repo.
func NewMemoryIncomingInviteRepo() *MemoryIncomingInviteRepo {
	return &MemoryIncomingInviteRepo{
		invites: make(map[string]*IncomingInvite),
	}
}

func (r *MemoryIncomingInviteRepo) Create(ctx context.Context, invite *IncomingInvite) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if invite.ID == "" {
		invite.ID = uuid.New().String()
	}
	if invite.ReceivedAt.IsZero() {
		invite.ReceivedAt = time.Now()
	}
	if invite.Status == "" {
		invite.Status = InviteStatusPending
	}

	r.invites[invite.ID] = invite
	return nil
}

func (r *MemoryIncomingInviteRepo) GetByID(ctx context.Context, id string) (*IncomingInvite, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	invite, ok := r.invites[id]
	if !ok {
		return nil, ErrInviteNotFound
	}
	return invite, nil
}

func (r *MemoryIncomingInviteRepo) List(ctx context.Context) ([]*IncomingInvite, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]*IncomingInvite, 0, len(r.invites))
	for _, invite := range r.invites {
		result = append(result, invite)
	}
	return result, nil
}

func (r *MemoryIncomingInviteRepo) UpdateStatus(ctx context.Context, id string, status InviteStatus) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	invite, ok := r.invites[id]
	if !ok {
		return ErrInviteNotFound
	}
	invite.Status = status
	return nil
}

func (r *MemoryIncomingInviteRepo) Delete(ctx context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.invites, id)
	return nil
}
