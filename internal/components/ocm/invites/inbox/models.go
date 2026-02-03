// Package inbox provides stored incoming invite models and repository.
package inbox

import (
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
)

// IncomingInvite represents an invite we received (via pasting an invite string).
type IncomingInvite struct {
	ID              string              `json:"id"`
	InviteString    string              `json:"inviteString"`
	Token           string              `json:"token"`
	SenderFQDN      string              `json:"senderFqdn"`
	RecipientUserID string              `json:"-"` // canonical local user id that owns this inbox entry
	ReceivedAt      time.Time           `json:"receivedAt"`
	Status          invites.InviteStatus `json:"status"`
}
