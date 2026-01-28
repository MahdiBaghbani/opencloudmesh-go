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
// All read/write operations are scoped to a specific recipient user id.
// Cross-user access behaves as not found (confidentiality invariant, Q2=B).
type IncomingInviteRepo interface {
	Create(ctx context.Context, invite *IncomingInvite) error
	GetByIDForRecipientUserID(ctx context.Context, id string, recipientUserID string) (*IncomingInvite, error)
	GetByTokenForRecipientUserID(ctx context.Context, token string, recipientUserID string) (*IncomingInvite, error)
	ListByRecipientUserID(ctx context.Context, recipientUserID string) ([]*IncomingInvite, error)
	UpdateStatusForRecipientUserID(ctx context.Context, id string, recipientUserID string, status InviteStatus) error
	DeleteForRecipientUserID(ctx context.Context, id string, recipientUserID string) error
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

// MemoryIncomingInviteRepo is an in-memory implementation with per-user scoping.
type MemoryIncomingInviteRepo struct {
	mu               sync.RWMutex
	invites          map[string]*IncomingInvite
	byRecipientUser  map[string][]string // recipientUserID -> []inviteID
	byTokenRecipient map[string]string   // "token\x00recipientUserID" -> inviteID
}

// NewMemoryIncomingInviteRepo creates a new in-memory incoming invite repo.
func NewMemoryIncomingInviteRepo() *MemoryIncomingInviteRepo {
	return &MemoryIncomingInviteRepo{
		invites:          make(map[string]*IncomingInvite),
		byRecipientUser:  make(map[string][]string),
		byTokenRecipient: make(map[string]string),
	}
}

// tokenRecipientKey builds the composite key for the byTokenRecipient index.
func tokenRecipientKey(token, recipientUserID string) string {
	return token + "\x00" + recipientUserID
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

	// Maintain recipient user index
	if invite.RecipientUserID != "" {
		r.byRecipientUser[invite.RecipientUserID] = append(
			r.byRecipientUser[invite.RecipientUserID], invite.ID)
	}

	// Maintain token+recipient index for idempotent import
	if invite.Token != "" && invite.RecipientUserID != "" {
		r.byTokenRecipient[tokenRecipientKey(invite.Token, invite.RecipientUserID)] = invite.ID
	}

	return nil
}

func (r *MemoryIncomingInviteRepo) GetByIDForRecipientUserID(ctx context.Context, id string, recipientUserID string) (*IncomingInvite, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	invite, ok := r.invites[id]
	if !ok || invite.RecipientUserID != recipientUserID {
		return nil, ErrInviteNotFound
	}
	return invite, nil
}

func (r *MemoryIncomingInviteRepo) GetByTokenForRecipientUserID(ctx context.Context, token string, recipientUserID string) (*IncomingInvite, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	id, ok := r.byTokenRecipient[tokenRecipientKey(token, recipientUserID)]
	if !ok {
		return nil, ErrInviteNotFound
	}
	invite, ok := r.invites[id]
	if !ok {
		return nil, ErrInviteNotFound
	}
	return invite, nil
}

func (r *MemoryIncomingInviteRepo) ListByRecipientUserID(ctx context.Context, recipientUserID string) ([]*IncomingInvite, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	ids := r.byRecipientUser[recipientUserID]
	result := make([]*IncomingInvite, 0, len(ids))
	for _, id := range ids {
		if invite, ok := r.invites[id]; ok {
			result = append(result, invite)
		}
	}
	return result, nil
}

func (r *MemoryIncomingInviteRepo) UpdateStatusForRecipientUserID(ctx context.Context, id string, recipientUserID string, status InviteStatus) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	invite, ok := r.invites[id]
	if !ok || invite.RecipientUserID != recipientUserID {
		return ErrInviteNotFound
	}
	invite.Status = status
	return nil
}

func (r *MemoryIncomingInviteRepo) DeleteForRecipientUserID(ctx context.Context, id string, recipientUserID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	invite, ok := r.invites[id]
	if !ok || invite.RecipientUserID != recipientUserID {
		return ErrInviteNotFound
	}

	// Clean up token+recipient index
	if invite.Token != "" {
		delete(r.byTokenRecipient, tokenRecipientKey(invite.Token, invite.RecipientUserID))
	}

	// Clean up recipient user index
	ids := r.byRecipientUser[invite.RecipientUserID]
	for i, iid := range ids {
		if iid == id {
			r.byRecipientUser[invite.RecipientUserID] = append(ids[:i], ids[i+1:]...)
			break
		}
	}

	delete(r.invites, id)
	return nil
}
