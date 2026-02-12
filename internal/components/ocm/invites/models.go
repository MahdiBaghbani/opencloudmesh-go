// Package invites provides shared types for OCM invitations. Subpackages: inbox (storage),
// outgoing (storage), incoming (POST /ocm/invite-accepted handler).
package invites

import (
	"encoding/base64"
	"errors"
	"strings"
	"time"
)

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

// CreateOutgoingRequest is the body for POST /api/invites/outgoing.
type CreateOutgoingRequest struct {
	RecipientEmail string `json:"recipientEmail,omitempty"`
	Description    string `json:"description,omitempty"`
}

// CreateOutgoingResponse is the body for POST /api/invites/outgoing response.
type CreateOutgoingResponse struct {
	InviteString string `json:"inviteString"`
	Token        string `json:"token"`
	ProviderFQDN string `json:"providerFqdn"`
	ExpiresAt    time.Time `json:"expiresAt"`
}

// ParseInviteString decodes base64 invite string; splits on last '@' into token and provider FQDN. Provider must not contain scheme.
func ParseInviteString(inviteString string) (token, providerFQDN string, err error) {
	decoded, err := base64.StdEncoding.DecodeString(inviteString)
	if err != nil {
		return "", "", errors.New("invalid base64 encoding")
	}

	inner := string(decoded)
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

func BuildInviteString(token, providerFQDN string) string {
	inner := token + "@" + providerFQDN
	return base64.StdEncoding.EncodeToString([]byte(inner))
}
