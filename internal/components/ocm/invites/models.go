// Package invites implements OCM invitation handling.
package invites

import (
	"encoding/base64"
	"errors"
	"strings"
	"time"
)

// InviteStatus represents the status of an invitation.
type InviteStatus string

const (
	InviteStatusPending  InviteStatus = "pending"
	InviteStatusAccepted InviteStatus = "accepted"
	InviteStatusDeclined InviteStatus = "declined"
	InviteStatusExpired  InviteStatus = "expired"
)

// OutgoingInvite represents an invite we sent to another server.
type OutgoingInvite struct {
	ID              string       `json:"id"`
	Token           string       `json:"token"`
	ProviderFQDN    string       `json:"providerFqdn"`
	InviteString    string       `json:"inviteString"`
	RecipientEmail  string       `json:"recipientEmail,omitempty"`
	CreatedByUserID string       `json:"-"` // local user id who created this invite
	CreatedAt       time.Time    `json:"createdAt"`
	ExpiresAt       time.Time    `json:"expiresAt"`
	Status          InviteStatus `json:"status"`
	AcceptedBy      string       `json:"acceptedBy,omitempty"`
	AcceptedAt      *time.Time   `json:"acceptedAt,omitempty"`
}

// IncomingInvite represents an invite we received (via pasting an invite string).
type IncomingInvite struct {
	ID              string       `json:"id"`
	InviteString    string       `json:"inviteString"`
	Token           string       `json:"token"`
	SenderFQDN      string       `json:"senderFqdn"`
	RecipientUserID string       `json:"-"` // canonical local user id that owns this inbox entry
	ReceivedAt      time.Time    `json:"receivedAt"`
	Status          InviteStatus `json:"status"`
}

// InviteAcceptedRequest is the server-to-server POST /ocm/invite-accepted body.
// All fields are spec-required (no omitempty).
type InviteAcceptedRequest struct {
	RecipientProvider string `json:"recipientProvider"`
	Token             string `json:"token"`
	UserID            string `json:"userID"`
	Email             string `json:"email"`
	Name              string `json:"name"`
}

// InviteAcceptedResponse is returned after successful invite acceptance.
// All fields are spec-required (no omitempty).
type InviteAcceptedResponse struct {
	UserID string `json:"userID"`
	Email  string `json:"email"`
	Name   string `json:"name"`
}

// CreateOutgoingRequest is the request for POST /api/invites/outgoing.
type CreateOutgoingRequest struct {
	RecipientEmail string `json:"recipientEmail,omitempty"`
	Description    string `json:"description,omitempty"`
}

// CreateOutgoingResponse is the response for POST /api/invites/outgoing.
type CreateOutgoingResponse struct {
	InviteString   string    `json:"inviteString"`
	Token          string    `json:"token"`
	ProviderFQDN   string    `json:"providerFqdn"`
	ExpiresAt      time.Time `json:"expiresAt"`
}

// InboxInviteView is the public view of an incoming invite.
type InboxInviteView struct {
	ID         string       `json:"id"`
	SenderFQDN string       `json:"senderFqdn"`
	ReceivedAt time.Time    `json:"receivedAt"`
	Status     InviteStatus `json:"status"`
}

// ParseInviteString parses a base64 invite string into token and provider FQDN.
// Format: base64("<token>@<provider_fqdn>")
// Provider FQDN must not contain scheme.
func ParseInviteString(inviteString string) (token, providerFQDN string, err error) {
	decoded, err := base64.StdEncoding.DecodeString(inviteString)
	if err != nil {
		return "", "", errors.New("invalid base64 encoding")
	}

	inner := string(decoded)

	// Must contain exactly one @
	atIdx := strings.LastIndex(inner, "@")
	if atIdx == -1 {
		return "", "", errors.New("invalid invite format: missing @")
	}

	token = inner[:atIdx]
	providerFQDN = inner[atIdx+1:]

	if token == "" {
		return "", "", errors.New("invalid invite format: empty token")
	}
	if providerFQDN == "" {
		return "", "", errors.New("invalid invite format: empty provider")
	}

	// Provider must not contain scheme
	if strings.Contains(providerFQDN, "://") {
		return "", "", errors.New("invalid invite format: provider contains scheme")
	}

	return token, providerFQDN, nil
}

// BuildInviteString creates a base64 invite string from token and provider FQDN.
func BuildInviteString(token, providerFQDN string) string {
	inner := token + "@" + providerFQDN
	return base64.StdEncoding.EncodeToString([]byte(inner))
}
