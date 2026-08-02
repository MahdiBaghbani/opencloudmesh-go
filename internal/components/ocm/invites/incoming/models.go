// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// Package incoming provides incoming invite models, repository, and the
// invite-accepted domain port used when we accept a received invite.
package incoming

import (
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
)

// IncomingInvite holds a received invite scoped to a local recipient user.
type IncomingInvite struct {
	ID              string               `json:"id"`
	InviteString    string               `json:"inviteString"`
	Token           string               `json:"token"`
	SenderFQDN      string               `json:"senderFqdn"`
	RecipientUserID string               `json:"-"` // canonical local user id that owns this inbox entry
	ReceivedAt      time.Time            `json:"receivedAt"`
	Status          invites.InviteStatus `json:"status"`
	// SenderUserID is the canonical remote sender user identity from the
	// accepted invite exchange (invite-accepted userID). Empty until the
	// invite is accepted.
	SenderUserID string `json:"senderUserId,omitempty"`
	// SenderFQDNNormalized is the sender FQDN in compare form (lowercase,
	// scheme-aware default-port stripped), persisted on acceptance so the
	// must-invite gate can compare hosts without re-normalizing.
	SenderFQDNNormalized string `json:"senderFqdnNormalized,omitempty"`
}

// Acceptance carries the remote sender identity observed when we accept
// a received invite (from the invite-accepted response).
type Acceptance struct {
	// UserID is the canonical remote sender user identity.
	UserID string
	// ProviderFQDN is the raw remote provider host.
	ProviderFQDN string
	// ProviderFQDNNormalized is the sender host in compare form.
	ProviderFQDNNormalized string
}
