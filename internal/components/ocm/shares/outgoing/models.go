// Package outgoing implements outgoing OCM share types and storage.
package outgoing

import (
	"time"
)

// OutgoingShare represents a share we created and sent to a receiver.
type OutgoingShare struct {
	// ShareID is the local ID (UUIDv7)
	ShareID string `json:"shareId"`

	// ProviderID is the share lifecycle ID sent to receiver
	ProviderID string `json:"providerId"`

	// WebDAVID is the WebDAV access ID for file serving
	WebDAVID string `json:"webdavId"`

	// SharedSecret for WebDAV access (never logged)
	SharedSecret string `json:"-"`

	// LocalPath is the local file path being shared
	LocalPath string `json:"localPath"`

	// ReceiverHost is the receiver's host
	ReceiverHost string `json:"receiverHost"`

	// ReceiverEndPoint is the discovered OCM endpoint
	ReceiverEndPoint string `json:"receiverEndPoint"`

	// ShareWith is the recipient OCM address
	ShareWith string `json:"shareWith"`

	// Metadata
	Name         string   `json:"name"`
	ResourceType string   `json:"resourceType"`
	ShareType    string   `json:"shareType"`
	Permissions  []string `json:"permissions"`

	// Sender identity
	Owner  string `json:"owner"`
	Sender string `json:"sender"`

	// State
	Status    string     `json:"status"` // pending, sent, failed
	CreatedAt time.Time  `json:"createdAt"`
	SentAt    *time.Time `json:"sentAt,omitempty"`
	Error     string     `json:"error,omitempty"`

	// MustExchangeToken indicates we advertised must-exchange-token requirement.
	// When true, /webdav/ocm/* rejects raw sharedSecret and accepts only exchanged tokens.
	MustExchangeToken bool `json:"mustExchangeToken"`
}

// OutgoingShareRequest is the request for POST /api/shares/outgoing.
type OutgoingShareRequest struct {
	ReceiverDomain string   `json:"receiverDomain"`
	ShareWith      string   `json:"shareWith"`
	LocalPath      string   `json:"localPath"`
	Name           string   `json:"name,omitempty"`
	Permissions    []string `json:"permissions"`
	ResourceType   string   `json:"resourceType,omitempty"`
}
