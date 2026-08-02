// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package outgoing

import (
	"context"

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
