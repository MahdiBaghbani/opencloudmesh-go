// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package incoming

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
)

// IncomingInviteRepo manages incoming invites; all ops scoped by recipient user id. Cross-user access = not found.
type IncomingInviteRepo interface {
	Create(ctx context.Context, invite *IncomingInvite) error
	GetByIDForRecipientUserID(ctx context.Context, id string, recipientUserID string) (*IncomingInvite, error)
	GetByTokenForRecipientUserID(ctx context.Context, token string, recipientUserID string) (*IncomingInvite, error)
	ListByRecipientUserID(ctx context.Context, recipientUserID string) ([]*IncomingInvite, error)
	// UpdateStatusForRecipientUserID sets the invite status; on acceptance the
	// remote sender identity from the invite-accepted exchange is persisted via
	// acceptance (nil for non-accepting updates).
	UpdateStatusForRecipientUserID(ctx context.Context, id string, recipientUserID string, status invites.InviteStatus, acceptance *Acceptance) error
	DeleteForRecipientUserID(ctx context.Context, id string, recipientUserID string) error
	// FindAcceptedForSender finds an accepted incoming invite for the local
	// recipientUserID whose remote sender matches both senderUserID and the
	// normalized sender host. Used by the bidirectional must-invite check.
	// Rows without a persisted normalized sender host never match.
	FindAcceptedForSender(ctx context.Context, recipientUserID string, senderUserID string, senderFQDNNormalized string) (*IncomingInvite, error)
}

// MemoryIncomingInviteRepo stores incoming invites in memory, scoped by recipient user id; implements IncomingInviteRepo.
type MemoryIncomingInviteRepo struct {
	mu               sync.RWMutex
	invites          map[string]*IncomingInvite
	byRecipientUser  map[string][]string // recipientUserID -> []inviteID
	byTokenRecipient map[string]string   // "token\x00recipientUserID" -> inviteID
}

func NewMemoryIncomingInviteRepo() *MemoryIncomingInviteRepo { //nolint:revive // exported: trivial constructor initializing the in-memory invite maps
	return &MemoryIncomingInviteRepo{
		invites:          make(map[string]*IncomingInvite),
		byRecipientUser:  make(map[string][]string),
		byTokenRecipient: make(map[string]string),
	}
}

func tokenRecipientKey(token, recipientUserID string) string {
	return token + "\x00" + recipientUserID
}

// Create stores the invite, assigning ID and defaults when empty; implements IncomingInviteRepo.
func (r *MemoryIncomingInviteRepo) Create(_ context.Context, invite *IncomingInvite) error {
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
	if invite.RecipientUserID != "" {
		r.byRecipientUser[invite.RecipientUserID] = append(
			r.byRecipientUser[invite.RecipientUserID], invite.ID)
	}

	if invite.Token != "" && invite.RecipientUserID != "" {
		r.byTokenRecipient[tokenRecipientKey(invite.Token, invite.RecipientUserID)] = invite.ID
	}

	return nil
}

// GetByIDForRecipientUserID returns the invite when its recipient matches; implements IncomingInviteRepo.
func (r *MemoryIncomingInviteRepo) GetByIDForRecipientUserID(_ context.Context, id string, recipientUserID string) (*IncomingInvite, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	invite, ok := r.invites[id]
	if !ok || invite.RecipientUserID != recipientUserID {
		return nil, invites.ErrInviteNotFound
	}

	return invite, nil
}

// GetByTokenForRecipientUserID returns the invite keyed by token and recipient; implements IncomingInviteRepo.
func (r *MemoryIncomingInviteRepo) GetByTokenForRecipientUserID(_ context.Context, token string, recipientUserID string) (*IncomingInvite, error) {
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

// ListByRecipientUserID returns all invites for the given recipient; implements IncomingInviteRepo.
func (r *MemoryIncomingInviteRepo) ListByRecipientUserID(_ context.Context, recipientUserID string) ([]*IncomingInvite, error) {
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

// UpdateStatusForRecipientUserID sets the invite status when the recipient matches; implements IncomingInviteRepo.
// On acceptance the remote sender identity is persisted alongside the status;
// the raw SenderFQDN stored at Create time is never rewritten here.
func (r *MemoryIncomingInviteRepo) UpdateStatusForRecipientUserID(_ context.Context, id string, recipientUserID string, status invites.InviteStatus, acceptance *Acceptance) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	invite, ok := r.invites[id]
	if !ok || invite.RecipientUserID != recipientUserID {
		return invites.ErrInviteNotFound
	}

	invite.Status = status

	if acceptance != nil {
		if acceptance.UserID != "" {
			invite.SenderUserID = acceptance.UserID
		}

		if acceptance.ProviderFQDNNormalized != "" {
			invite.SenderFQDNNormalized = acceptance.ProviderFQDNNormalized
		}
	}

	return nil
}

// FindAcceptedForSender finds an accepted incoming invite for the local
// recipient whose remote sender matches the given user and normalized host;
// implements IncomingInviteRepo.
func (r *MemoryIncomingInviteRepo) FindAcceptedForSender(_ context.Context, recipientUserID string, senderUserID string, senderFQDNNormalized string) (*IncomingInvite, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, id := range r.byRecipientUser[recipientUserID] {
		invite, ok := r.invites[id]
		if !ok || invite.Status != invites.InviteStatusAccepted {
			continue
		}

		if invite.SenderUserID != senderUserID {
			continue
		}

		// Rows without a persisted normalized sender host never match, even
		// against an empty query value.
		if invite.SenderFQDNNormalized == "" || invite.SenderFQDNNormalized != senderFQDNNormalized {
			continue
		}

		return invite, nil
	}

	return nil, invites.ErrInviteNotFound
}

// DeleteForRecipientUserID removes the invite and its indexes when the recipient matches; implements IncomingInviteRepo.
func (r *MemoryIncomingInviteRepo) DeleteForRecipientUserID(_ context.Context, id string, recipientUserID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	invite, ok := r.invites[id]
	if !ok || invite.RecipientUserID != recipientUserID {
		return invites.ErrInviteNotFound
	}

	if invite.Token != "" {
		delete(r.byTokenRecipient, tokenRecipientKey(invite.Token, invite.RecipientUserID))
	}

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
