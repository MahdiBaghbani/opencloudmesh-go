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
	ShareId    string `json:"share_id" gorm:"uniqueIndex"`   // sender-local identity (UUIDv7)
	ProviderId string `json:"provider_id" gorm:"primaryKey"` // provider-assigned share id
	WebDAVId   string `json:"webdav_id" gorm:"uniqueIndex"`
	// omitempty for redaction; partial unique index enforces non-empty secret
	// uniqueness in SQL backends (empty shared secrets are allowed on many rows).
	SharedSecret     string   `json:"shared_secret,omitempty" gorm:"uniqueIndex:idx_outgoing_shares_secret,where:shared_secret <> ''"`
	LocalPath        string   `json:"local_path"`
	Owner            string   `json:"owner"`
	Sender           string   `json:"sender"`
	ShareWith        string   `json:"share_with"`
	ReceiverHost     string   `json:"receiver_host"`
	ReceiverEndPoint string   `json:"receiver_end_point"`
	Name             string   `json:"name"`
	ResourceType     string   `json:"resource_type"`
	ShareType        string   `json:"share_type"`
	Permissions      string   `json:"permissions"`
	State            string   `json:"state"` // sent, accepted, declined
	Error            string   `json:"error,omitempty"`
	Requirements     []string `json:"requirements,omitempty" gorm:"serializer:json"`
	CreatedAt        int64    `json:"created_at"`
	UpdatedAt        int64    `json:"updated_at"`
}

// IncomingShare represents a share received by this instance (receiver-side).
// The composite unique index on (sending_server, provider_id) enforces that one
// provider-key pair can be stored at most once, matching GetIncomingShareByProviderKey
// singular semantics.
type IncomingShare struct {
	ShareId           string `json:"share_id" gorm:"primaryKey"`                                         // receiver-local id (UUIDv7)
	SendingServer     string `json:"sending_server" gorm:"uniqueIndex:idx_incoming_shares_provider_key"` // sender's host
	ProviderId        string `json:"provider_id" gorm:"uniqueIndex:idx_incoming_shares_provider_key"`    // sender's share id
	WebDAVId          string `json:"webdav_id,omitempty"`                                                // relative or absolute webdav URI
	SharedSecret      string `json:"shared_secret,omitempty"`                                            // omitempty for redaction
	Owner             string `json:"owner"`
	Sender            string `json:"sender"`
	ShareWith         string `json:"share_with"`
	Name              string `json:"name"`
	Description       string `json:"description,omitempty"`
	ResourceType      string `json:"resource_type"`
	ShareType         string `json:"share_type"`
	OwnerDisplayName  string `json:"owner_display_name,omitempty"`
	SenderDisplayName string `json:"sender_display_name,omitempty"`
	Permissions       string `json:"permissions"`
	// Webapp arm columns. WebappPermissions mirrors the comma-joined
	// Permissions pattern; WebappTargets uses the json serializer like
	// Requirements. Legacy rows leave these empty.
	WebappPermissions string   `json:"webapp_permissions,omitempty"`
	WebappURI         string   `json:"webapp_uri,omitempty"`
	WebappTargets     []string `json:"webapp_targets,omitempty" gorm:"serializer:json"`
	ProtocolName      string   `json:"protocol_name,omitempty"`
	State             string   `json:"state"` // pending, accepted, declined
	UserId            string   `json:"user_id" gorm:"index"`
	OwnerHost         string   `json:"owner_host"`
	Requirements      []string `json:"requirements,omitempty" gorm:"serializer:json"`
	// Expiration is a Unix epoch; 0 means no expiration.
	Expiration int64 `json:"expiration,omitempty"`
	CreatedAt  int64 `json:"created_at"`
	UpdatedAt  int64 `json:"updated_at"`
}

// OutgoingInvite is the persistence model for outgoing invites (initiator-side).
type OutgoingInvite struct {
	ID              string `json:"id" gorm:"primaryKey"`
	Token           string `json:"token" gorm:"uniqueIndex"`
	ProviderFQDN    string `json:"provider_fqdn"`
	InviteString    string `json:"invite_string"`
	RecipientEmail  string `json:"recipient_email,omitempty"`
	CreatedByUserId string `json:"created_by_user_id" gorm:"index"`
	Status          string `json:"status"` // pending, accepted, declined, expired
	AcceptedBy      string `json:"accepted_by,omitempty"`
	ExpiresAt       int64  `json:"expires_at"`
	CreatedAt       int64  `json:"created_at"`
	UpdatedAt       int64  `json:"updated_at"`
	AcceptedAt      int64  `json:"accepted_at,omitempty"` // unix epoch; 0 = not yet accepted
}

// IncomingInvite is the persistence model for incoming invites (acceptor-side).
// The composite unique index on (token, recipient_user_id) enforces that one
// recipient can accept any given token at most once.
type IncomingInvite struct {
	ID              string `json:"id" gorm:"primaryKey"`
	Token           string `json:"token" gorm:"uniqueIndex:idx_incoming_invites_token_recipient"`
	InviteString    string `json:"invite_string"`
	SenderFQDN      string `json:"sender_fqdn"`
	RecipientUserId string `json:"recipient_user_id" gorm:"uniqueIndex:idx_incoming_invites_token_recipient"`
	Status          string `json:"status"` // pending, accepted
	ReceivedAt      int64  `json:"received_at"`
	UpdatedAt       int64  `json:"updated_at"`
}
