// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package outgoing

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
)

type OutgoingInviteRepo interface { //nolint:revive // exported: self-explanatory CRUD interface for outgoing invites
	Create(ctx context.Context, invite *OutgoingInvite) error
	GetByID(ctx context.Context, id string) (*OutgoingInvite, error)
	GetByToken(ctx context.Context, token string) (*OutgoingInvite, error)
	List(ctx context.Context) ([]*OutgoingInvite, error)
	UpdateStatus(ctx context.Context, id string, status invites.InviteStatus, acceptance *Acceptance) error
	// FindAcceptedForRecipient finds an accepted outgoing invite created by the
	// local senderUserID whose remote accepter matches both recipientUserID and
	// the normalized recipient host. Used by the bidirectional must-invite
	// check. Rows without a persisted normalized provider host never match.
	FindAcceptedForRecipient(ctx context.Context, senderUserID string, recipientUserID string, recipientFQDNNormalized string) (*OutgoingInvite, error)
}

// MemoryOutgoingInviteRepo stores outgoing invites in memory; implements OutgoingInviteRepo.
type MemoryOutgoingInviteRepo struct {
	mu      sync.RWMutex
	invites map[string]*OutgoingInvite
	byToken map[string]string // token -> id
}

func NewMemoryOutgoingInviteRepo() *MemoryOutgoingInviteRepo { //nolint:revive // exported: trivial constructor initializing the in-memory invite maps
	return &MemoryOutgoingInviteRepo{
		invites: make(map[string]*OutgoingInvite),
		byToken: make(map[string]string),
	}
}

// Create stores the invite, assigning ID and defaults when empty; implements OutgoingInviteRepo.
func (r *MemoryOutgoingInviteRepo) Create(_ context.Context, invite *OutgoingInvite) error {
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

// GetByID returns the invite with the given id; implements OutgoingInviteRepo.
func (r *MemoryOutgoingInviteRepo) GetByID(_ context.Context, id string) (*OutgoingInvite, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	invite, ok := r.invites[id]
	if !ok {
		return nil, invites.ErrInviteNotFound
	}

	return invite, nil
}

// GetByToken returns the invite with the given token; implements OutgoingInviteRepo.
func (r *MemoryOutgoingInviteRepo) GetByToken(_ context.Context, token string) (*OutgoingInvite, error) {
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

// List returns all stored invites; implements OutgoingInviteRepo.
func (r *MemoryOutgoingInviteRepo) List(_ context.Context) ([]*OutgoingInvite, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]*OutgoingInvite, 0, len(r.invites))
	for _, invite := range r.invites {
		result = append(result, invite)
	}

	return result, nil
}

// UpdateStatus sets the invite status and acceptance metadata; implements OutgoingInviteRepo.
func (r *MemoryOutgoingInviteRepo) UpdateStatus(_ context.Context, id string, status invites.InviteStatus, acceptance *Acceptance) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	invite, ok := r.invites[id]
	if !ok {
		return invites.ErrInviteNotFound
	}

	invite.Status = status

	if acceptance != nil {
		if acceptance.ProviderFQDN != "" {
			invite.AcceptedProviderFQDN = acceptance.ProviderFQDN
		}

		if acceptance.UserID != "" {
			invite.AcceptedUserID = acceptance.UserID
		}

		if acceptance.ProviderFQDNNormalized != "" {
			invite.AcceptedProviderFQDNNormalized = acceptance.ProviderFQDNNormalized
		}

		now := time.Now()
		invite.AcceptedAt = &now
	}

	return nil
}

// FindAcceptedForRecipient finds an accepted outgoing invite created by the
// local sender whose remote accepter matches the given user and normalized
// host; implements OutgoingInviteRepo.
func (r *MemoryOutgoingInviteRepo) FindAcceptedForRecipient(_ context.Context, senderUserID string, recipientUserID string, recipientFQDNNormalized string) (*OutgoingInvite, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, invite := range r.invites {
		if invite.Status != invites.InviteStatusAccepted {
			continue
		}

		if invite.CreatedByUserID != senderUserID || invite.AcceptedUserID != recipientUserID {
			continue
		}

		// Rows without a persisted normalized provider host never match, even
		// against an empty query value.
		if invite.AcceptedProviderFQDNNormalized == "" || invite.AcceptedProviderFQDNNormalized != recipientFQDNNormalized {
			continue
		}

		return invite, nil
	}

	return nil, invites.ErrInviteNotFound
}
