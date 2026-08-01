// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package incoming

import (
	"context"

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
