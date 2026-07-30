// Package invites provides shared types for OCM invitations. Subpackages: inbox (storage),
// outgoing (storage), incoming (POST /ocm/invite-accepted handler).
package invites

import (
	"encoding/base64"
	"errors"
	"strings"
	"time"
)

// InviteStatus tracks the lifecycle state of an OCM invite (pending, accepted, declined, expired).
type InviteStatus string

const (
	// InviteStatusPending is the pending invite status.
	InviteStatusPending InviteStatus = "pending"
	// InviteStatusAccepted is the accepted invite status.
	InviteStatusAccepted InviteStatus = "accepted"
	// InviteStatusDeclined is the declined invite status.
	InviteStatusDeclined InviteStatus = "declined"
	// InviteStatusExpired is the expired invite status.
	InviteStatusExpired InviteStatus = "expired"
)

var (
	// ErrInviteNotFound reports a missing invite.
	ErrInviteNotFound = errors.New("invite not found")
	// ErrTokenNotFound reports a missing invite token.
	ErrTokenNotFound = errors.New("token not found")
)

// CreateOutgoingRequest is the body for POST /api/invites/outgoing.
type CreateOutgoingRequest struct {
	RecipientEmail string `json:"recipientEmail,omitempty"`
	Description    string `json:"description,omitempty"`
}

// CreateOutgoingResponse is the body for POST /api/invites/outgoing response.
type CreateOutgoingResponse struct {
	InviteString string    `json:"inviteString"`
	Token        string    `json:"token"`
	ProviderFQDN string    `json:"providerFqdn"`
	ExpiresAt    time.Time `json:"expiresAt"`
}

// ParseInviteString decodes a base64url invite string, accepting padded or unpadded
// base64url and legacy standard base64, then splits on the last '@' into token and
// provider FQDN. Provider must not contain scheme.
// See https://github.com/cs3org/OCM-API/blob/6a0586183cbef10ecae9dedc42561806447eb2f5/IETF-OCM.md#L485-L498
func ParseInviteString(inviteString string) (token, providerFQDN string, err error) {
	var (
		decoded   []byte
		decodeErr error
	)
	for _, enc := range []*base64.Encoding{
		base64.URLEncoding,
		base64.RawURLEncoding,
		base64.StdEncoding,
	} {
		decoded, decodeErr = enc.DecodeString(inviteString)
		if decodeErr == nil {
			break
		}
	}

	if decodeErr != nil {
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

// BuildInviteString joins token and provider FQDN with '@' and encodes the result
// using base64url (RFC 4648 Section 5) with padding omitted.
// See https://github.com/cs3org/OCM-API/blob/6a0586183cbef10ecae9dedc42561806447eb2f5/IETF-OCM.md#L127-L130
func BuildInviteString(token, providerFQDN string) string {
	inner := token + "@" + providerFQDN
	return base64.RawURLEncoding.EncodeToString([]byte(inner))
}
