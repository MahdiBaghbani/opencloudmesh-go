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

// ShareStore defines operations for share persistence.
// This interface will be implemented by concrete drivers.
type ShareStore interface {
	// Outgoing shares (sender-side)
	CreateOutgoingShare(ctx context.Context, share *OutgoingShare) error
	GetOutgoingShare(ctx context.Context, providerId string) (*OutgoingShare, error)
	GetOutgoingShareByWebDAVId(ctx context.Context, webdavId string) (*OutgoingShare, error)
	UpdateOutgoingShare(ctx context.Context, share *OutgoingShare) error
	DeleteOutgoingShare(ctx context.Context, providerId string) error
	ListOutgoingShares(ctx context.Context) ([]*OutgoingShare, error)

	// Incoming shares (receiver-side)
	CreateIncomingShare(ctx context.Context, share *IncomingShare) error
	GetIncomingShare(ctx context.Context, shareId string) (*IncomingShare, error)
	GetIncomingShareByProviderKey(ctx context.Context, sendingServer, providerId string) (*IncomingShare, error)
	UpdateIncomingShare(ctx context.Context, share *IncomingShare) error
	DeleteIncomingShare(ctx context.Context, shareId string) error
	ListIncomingShares(ctx context.Context, userId string) ([]*IncomingShare, error)
}

// InviteStore defines operations for invite persistence.
type InviteStore interface {
	CreateInvite(ctx context.Context, invite *Invite) error
	GetInvite(ctx context.Context, token string) (*Invite, error)
	UpdateInvite(ctx context.Context, invite *Invite) error
	DeleteInvite(ctx context.Context, token string) error
	ListInvites(ctx context.Context, userId string) ([]*Invite, error)
}

// OutgoingShare represents a share created by this instance (sender-side).
type OutgoingShare struct {
	ProviderId   string `json:"provider_id" gorm:"primaryKey"`
	WebDAVId     string `json:"webdav_id" gorm:"uniqueIndex"`
	SharedSecret string `json:"shared_secret,omitempty"` // omitempty for redaction
	LocalPath    string `json:"local_path"`
	Owner        string `json:"owner"`
	Sender       string `json:"sender"`
	ShareWith    string `json:"share_with"`
	ReceiverHost string `json:"receiver_host"`
	Name         string `json:"name"`
	ResourceType string `json:"resource_type"`
	Permissions  string `json:"permissions"`
	State        string `json:"state"` // pending, accepted, declined
	CreatedAt    int64  `json:"created_at"`
	UpdatedAt    int64  `json:"updated_at"`
}

// IncomingShare represents a share received by this instance (receiver-side).
type IncomingShare struct {
	ShareId        string `json:"share_id" gorm:"primaryKey"`         // receiver-local id (UUIDv7)
	SendingServer  string `json:"sending_server" gorm:"index"`        // sender's host
	ProviderId     string `json:"provider_id" gorm:"index"`           // sender's share id
	WebDAVId       string `json:"webdav_id,omitempty"`                // relative webdav path
	WebDAVUriAbs   string `json:"webdav_uri_absolute,omitempty"`      // absolute URI (deprecated)
	SharedSecret   string `json:"shared_secret,omitempty"`            // omitempty for redaction
	Owner          string `json:"owner"`
	Sender         string `json:"sender"`
	ShareWith      string `json:"share_with"`
	Name           string `json:"name"`
	ResourceType   string `json:"resource_type"`
	Permissions    string `json:"permissions"`
	State          string `json:"state"` // pending, accepted, declined
	UserId         string `json:"user_id" gorm:"index"`
	CreatedAt      int64  `json:"created_at"`
	UpdatedAt      int64  `json:"updated_at"`
}

// Invite represents an OCM invite token.
type Invite struct {
	Token       string `json:"token" gorm:"primaryKey"`
	UserId      string `json:"user_id" gorm:"index"`
	Provider    string `json:"provider"`    // our provider FQDN
	RemoteUser  string `json:"remote_user"` // remote user who accepted
	RemoteHost  string `json:"remote_host"` // remote provider host
	State       string `json:"state"`       // pending, accepted
	ExpiresAt   int64  `json:"expires_at"`
	CreatedAt   int64  `json:"created_at"`
	UpdatedAt   int64  `json:"updated_at"`
}
