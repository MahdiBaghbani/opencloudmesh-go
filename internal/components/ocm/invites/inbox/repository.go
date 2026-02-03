package inbox

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
)

// IncomingInviteRepo manages incoming invites.
// All read/write operations are scoped to a specific recipient user id.
// Cross-user access behaves as not found (confidentiality invariant).
type IncomingInviteRepo interface {
	Create(ctx context.Context, invite *IncomingInvite) error
	GetByIDForRecipientUserID(ctx context.Context, id string, recipientUserID string) (*IncomingInvite, error)
	GetByTokenForRecipientUserID(ctx context.Context, token string, recipientUserID string) (*IncomingInvite, error)
	ListByRecipientUserID(ctx context.Context, recipientUserID string) ([]*IncomingInvite, error)
	UpdateStatusForRecipientUserID(ctx context.Context, id string, recipientUserID string, status invites.InviteStatus) error
	DeleteForRecipientUserID(ctx context.Context, id string, recipientUserID string) error
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
		invite.Status = invites.InviteStatusPending
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
		return nil, invites.ErrInviteNotFound
	}
	return invite, nil
}

func (r *MemoryIncomingInviteRepo) GetByTokenForRecipientUserID(ctx context.Context, token string, recipientUserID string) (*IncomingInvite, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	id, ok := r.byTokenRecipient[tokenRecipientKey(token, recipientUserID)]
	if !ok {
		return nil, invites.ErrInviteNotFound
	}
	invite, ok := r.invites[id]
	if !ok {
		return nil, invites.ErrInviteNotFound
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

func (r *MemoryIncomingInviteRepo) UpdateStatusForRecipientUserID(ctx context.Context, id string, recipientUserID string, status invites.InviteStatus) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	invite, ok := r.invites[id]
	if !ok || invite.RecipientUserID != recipientUserID {
		return invites.ErrInviteNotFound
	}
	invite.Status = status
	return nil
}

func (r *MemoryIncomingInviteRepo) DeleteForRecipientUserID(ctx context.Context, id string, recipientUserID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	invite, ok := r.invites[id]
	if !ok || invite.RecipientUserID != recipientUserID {
		return invites.ErrInviteNotFound
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
