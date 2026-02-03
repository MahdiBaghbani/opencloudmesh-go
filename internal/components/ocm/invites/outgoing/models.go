// Package outgoing provides stored outgoing invite models and repository.
package outgoing

import (
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
)

// OutgoingInvite represents an invite we sent to another server.
type OutgoingInvite struct {
	ID              string              `json:"id"`
	Token           string              `json:"token"`
	ProviderFQDN    string              `json:"providerFqdn"`
	InviteString    string              `json:"inviteString"`
	RecipientEmail  string              `json:"recipientEmail,omitempty"`
	CreatedByUserID string              `json:"-"` // local user id who created this invite
	CreatedAt       time.Time           `json:"createdAt"`
	ExpiresAt       time.Time           `json:"expiresAt"`
	Status          invites.InviteStatus `json:"status"`
	AcceptedBy      string              `json:"acceptedBy,omitempty"`
	AcceptedAt      *time.Time          `json:"acceptedAt,omitempty"`
}
