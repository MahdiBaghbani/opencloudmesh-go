// Package store provides persistence primitives and driver abstractions.
package store

import (
	"context"
	"errors"
)

// Common errors for store operations.
var (
	ErrNotFound      = errors.New("not found")
	ErrAlreadyExists = errors.New("already exists")
	ErrClosed        = errors.New("store closed")
)

// Driver defines the interface for a persistence backend.
// Implementations must be safe for concurrent use.
type Driver interface {
	// Init initializes the driver (create tables, load data, etc).
	Init(ctx context.Context) error

	// Close releases resources held by the driver.
	Close() error

	// Name returns the driver name (json, sqlite, mirror).
	Name() string
}

// OutgoingShareStore manages outgoing share persistence (sender-side).
// Lookup is available by local share id, provider id, webdav id, and shared secret.
type OutgoingShareStore interface {
	CreateOutgoingShare(ctx context.Context, share *OutgoingShare) error
	GetOutgoingShareByID(ctx context.Context, shareId string) (*OutgoingShare, error)
	GetOutgoingShare(ctx context.Context, providerId string) (*OutgoingShare, error)
	GetOutgoingShareByWebDAVId(ctx context.Context, webdavId string) (*OutgoingShare, error)
	GetOutgoingShareBySharedSecret(ctx context.Context, sharedSecret string) (*OutgoingShare, error)
	UpdateOutgoingShare(ctx context.Context, share *OutgoingShare) error
	DeleteOutgoingShare(ctx context.Context, providerId string) error
	ListOutgoingShares(ctx context.Context) ([]*OutgoingShare, error)
}

// IncomingShareStore manages incoming share persistence (receiver-side).
// All mutating operations are scoped by recipientUserId to prevent cross-user access.
type IncomingShareStore interface {
	CreateIncomingShare(ctx context.Context, share *IncomingShare) error
	GetIncomingShareByIDForRecipient(ctx context.Context, shareId string, recipientUserId string) (*IncomingShare, error)
	GetIncomingShareByProviderKey(ctx context.Context, sendingServer, providerId string) (*IncomingShare, error)
	ListIncomingSharesByRecipient(ctx context.Context, recipientUserId string) ([]*IncomingShare, error)
	UpdateIncomingShareStatusForRecipient(ctx context.Context, shareId string, recipientUserId string, state string) error
	DeleteIncomingShareForRecipient(ctx context.Context, shareId string, recipientUserId string) error
}

// OutgoingInviteStore manages outgoing invite persistence (initiator-side).
type OutgoingInviteStore interface {
	CreateOutgoingInvite(ctx context.Context, invite *OutgoingInvite) error
	GetOutgoingInvite(ctx context.Context, id string) (*OutgoingInvite, error)
	GetOutgoingInviteByToken(ctx context.Context, token string) (*OutgoingInvite, error)
	UpdateOutgoingInvite(ctx context.Context, invite *OutgoingInvite) error
	DeleteOutgoingInvite(ctx context.Context, id string) error
	ListOutgoingInvites(ctx context.Context, userId string) ([]*OutgoingInvite, error)
}

// IncomingInviteStore manages incoming invite persistence (acceptor-side).
// All mutating operations are scoped by recipientUserId to prevent cross-user access.
// Update is intentionally status-only: scope-defining fields (Token, RecipientUserId)
// cannot be reassigned after creation.
type IncomingInviteStore interface {
	CreateIncomingInvite(ctx context.Context, invite *IncomingInvite) error
	GetIncomingInviteForRecipient(ctx context.Context, id string, recipientUserId string) (*IncomingInvite, error)
	GetIncomingInviteByToken(ctx context.Context, token string, recipientUserId string) (*IncomingInvite, error)
	UpdateIncomingInviteStatusForRecipient(ctx context.Context, id string, recipientUserId string, status string) error
	DeleteIncomingInviteForRecipient(ctx context.Context, id string, recipientUserId string) error
	ListIncomingInvites(ctx context.Context, recipientUserId string) ([]*IncomingInvite, error)
}

// OutgoingShare represents a share created by this instance (sender-side).
type OutgoingShare struct {
	ShareId    string `gorm:"uniqueIndex" json:"shareId"`    // sender-local identity (UUIDv7)
	ProviderId string `gorm:"primaryKey"  json:"providerId"` // provider-assigned share id
	WebDAVId   string `gorm:"uniqueIndex" json:"webdavId"`
	// omitempty for redaction; partial unique index enforces non-empty secret
	// uniqueness in SQL backends (empty shared secrets are allowed on many rows).
	SharedSecret     string   `gorm:"uniqueIndex:idx_outgoing_shares_secret,where:shared_secret <> ''" json:"sharedSecret,omitempty"`
	LocalPath        string   `json:"localPath"`
	Owner            string   `json:"owner"`
	Sender           string   `json:"sender"`
	ShareWith        string   `json:"shareWith"`
	ReceiverHost     string   `json:"receiverHost"`
	ReceiverEndPoint string   `json:"receiverEndPoint"`
	Name             string   `json:"name"`
	ResourceType     string   `json:"resourceType"`
	ShareType        string   `json:"shareType"`
	Permissions      string   `json:"permissions"`
	State            string   `json:"state"` // sent, accepted, declined
	Error            string   `json:"error,omitempty"`
	Requirements     []string `gorm:"serializer:json"                                                  json:"requirements,omitempty"`
	CreatedAt        int64    `json:"createdAt"`
	UpdatedAt        int64    `json:"updatedAt"`
}

// IncomingShare represents a share received by this instance (receiver-side).
// The composite unique index on (sendingServer, providerId) enforces that one
// provider-key pair can be stored at most once, matching GetIncomingShareByProviderKey
// singular semantics.
type IncomingShare struct {
	ShareId           string `gorm:"primaryKey"                                   json:"shareId"`       // receiver-local id (UUIDv7)
	SendingServer     string `gorm:"uniqueIndex:idx_incoming_shares_provider_key" json:"sendingServer"` // sender's host
	ProviderId        string `gorm:"uniqueIndex:idx_incoming_shares_provider_key" json:"providerId"`    // sender's share id
	WebDAVId          string `json:"webdavId,omitempty"`                                                // relative or absolute webdav URI
	SharedSecret      string `json:"sharedSecret,omitempty"`                                            // omitempty for redaction
	Owner             string `json:"owner"`
	Sender            string `json:"sender"`
	ShareWith         string `json:"shareWith"`
	Name              string `json:"name"`
	Description       string `json:"description,omitempty"`
	ResourceType      string `json:"resourceType"`
	ShareType         string `json:"shareType"`
	OwnerDisplayName  string `json:"ownerDisplayName,omitempty"`
	SenderDisplayName string `json:"senderDisplayName,omitempty"`
	Permissions       string `json:"permissions"`
	// Webapp arm columns. WebappPermissions mirrors the comma-joined
	// Permissions pattern; WebappTargets uses the json serializer like
	// Requirements. Legacy rows leave these empty.
	WebappPermissions string   `json:"webappPermissions,omitempty"`
	WebappURI         string   `json:"webappUri,omitempty"`
	WebappTargets     []string `gorm:"serializer:json"              json:"webappTargets,omitempty"`
	ProtocolName      string   `json:"protocolName,omitempty"`
	State             string   `json:"state"` // pending, accepted, declined
	UserId            string   `gorm:"index"                        json:"userId"`
	OwnerHost         string   `json:"ownerHost"`
	Requirements      []string `gorm:"serializer:json"              json:"requirements,omitempty"`
	// Expiration is a Unix epoch; 0 means no expiration.
	Expiration int64 `json:"expiration,omitempty"`
	CreatedAt  int64 `json:"createdAt"`
	UpdatedAt  int64 `json:"updatedAt"`
}

// OutgoingInvite is the persistence model for outgoing invites (initiator-side).
type OutgoingInvite struct {
	ID              string `gorm:"primaryKey"                json:"id"`
	Token           string `gorm:"uniqueIndex"               json:"token"`
	ProviderFQDN    string `json:"providerFqdn"`
	InviteString    string `json:"inviteString"`
	RecipientEmail  string `json:"recipientEmail,omitempty"`
	CreatedByUserId string `gorm:"index"                     json:"createdByUserId"`
	Status          string `json:"status"` // pending, accepted, declined, expired
	AcceptedBy      string `json:"acceptedBy,omitempty"`
	ExpiresAt       int64  `json:"expiresAt"`
	CreatedAt       int64  `json:"createdAt"`
	UpdatedAt       int64  `json:"updatedAt"`
	AcceptedAt      int64  `json:"acceptedAt,omitempty"` // unix epoch; 0 = not yet accepted
}

// IncomingInvite is the persistence model for incoming invites (acceptor-side).
// The composite unique index on (token, recipientUserId) enforces that one
// recipient can accept any given token at most once.
type IncomingInvite struct {
	ID              string `gorm:"primaryKey"                                       json:"id"`
	Token           string `gorm:"uniqueIndex:idx_incoming_invites_token_recipient" json:"token"`
	InviteString    string `json:"inviteString"`
	SenderFQDN      string `json:"senderFqdn"`
	RecipientUserId string `gorm:"uniqueIndex:idx_incoming_invites_token_recipient" json:"recipientUserId"`
	Status          string `json:"status"` // pending, accepted
	ReceivedAt      int64  `json:"receivedAt"`
	UpdatedAt       int64  `json:"updatedAt"`
}
