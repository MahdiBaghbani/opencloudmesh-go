// Package outgoing provides outgoing invite models and repository.
package outgoing

import (
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
)

// OutgoingInvite holds an invite created locally for a remote recipient.
type OutgoingInvite struct {
	ID              string               `json:"id"`
	Token           string               `json:"token"`
	ProviderFQDN    string               `json:"providerFqdn"`
	InviteString    string               `json:"inviteString"`
	RecipientEmail  string               `json:"recipientEmail,omitempty"`
	CreatedByUserID string               `json:"-"` // local user id who created this invite
	CreatedAt       time.Time            `json:"createdAt"`
	ExpiresAt       time.Time            `json:"expiresAt"`
	Status          invites.InviteStatus `json:"status"`
	// AcceptedProviderFQDN is the raw remote provider host sent on the wire as
	// recipientProvider when the invite was accepted.
	AcceptedProviderFQDN string     `json:"acceptedProviderFqdn,omitempty"`
	AcceptedAt           *time.Time `json:"acceptedAt,omitempty"`
	// AcceptedUserID is the canonical remote accepter user identity from the
	// invite-accepted request (userID).
	AcceptedUserID string `json:"acceptedUserId,omitempty"`
	// AcceptedProviderFQDNNormalized is the accepting provider FQDN in compare
	// form (lowercase, scheme-aware default-port stripped), persisted separately
	// from AcceptedProviderFQDN so the must-invite gate can compare hosts
	// without re-normalizing.
	AcceptedProviderFQDNNormalized string `json:"acceptedProviderFqdnNormalized,omitempty"`
}

// Acceptance carries the remote accepter identity observed when an outgoing
// invite is accepted, per the invite-accepted protocol request:
// https://github.com/cs3org/OCM-API/blob/6a0586183cbef10ecae9dedc42561806447eb2f5/IETF-OCM.md
type Acceptance struct {
	// ProviderFQDN is the raw remote provider host from the invite-accepted
	// request (recipientProvider as sent on the wire).
	ProviderFQDN string
	// UserID is the canonical remote accepter user identity (invite-accepted userID).
	UserID string
	// ProviderFQDNNormalized is the accepting provider in host compare form.
	ProviderFQDNNormalized string
}
