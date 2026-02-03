// Package invites provides shared types for OCM invitation handling.
// Domain models and repositories live in direction-aware sub-packages:
//   - invites/inbox: incoming invite storage (IncomingInvite, IncomingInviteRepo)
//   - invites/outgoing: outgoing invite storage (OutgoingInvite, OutgoingInviteRepo)
//   - invites/incoming: inbound OCM protocol handler (POST /ocm/invite-accepted)
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

var (
	ErrInviteNotFound = errors.New("invite not found")
	ErrTokenNotFound  = errors.New("token not found")
)

// CreateOutgoingRequest is the request for POST /api/invites/outgoing.
type CreateOutgoingRequest struct {
	RecipientEmail string `json:"recipientEmail,omitempty"`
	Description    string `json:"description,omitempty"`
}

// CreateOutgoingResponse is the response for POST /api/invites/outgoing.
type CreateOutgoingResponse struct {
	InviteString string `json:"inviteString"`
	Token        string `json:"token"`
	ProviderFQDN string `json:"providerFqdn"`
	ExpiresAt    time.Time `json:"expiresAt"`
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
