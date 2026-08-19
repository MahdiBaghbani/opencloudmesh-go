// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

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

	// ErrNoSharedSQLiteHandle is returned when a caller needs a shared SQLite
	// handle but the active persistence backend does not implement SQLiteBacked.
	ErrNoSharedSQLiteHandle = errors.New("persistence backend does not provide a shared SQLite handle")
)

// Driver defines the interface for a persistence backend.
// Implementations must be safe for concurrent use.
type Driver interface {
	// Init initializes the driver (create tables, load data, etc).
	Init(ctx context.Context) error

	// Close releases resources held by the driver.
	Close() error

	// Name returns the driver name (memory, json, sqlite, mirror).
	Name() string
}

// OutgoingShareStore manages outgoing share persistence (sender-side).
// Lookup is available by local share id, provider id, webdav id, and shared secret.
type OutgoingShareStore interface {
	CreateOutgoingShare(ctx context.Context, share *OutgoingShare) error
	GetOutgoingShareByID(ctx context.Context, shareID string) (*OutgoingShare, error)
	GetOutgoingShare(ctx context.Context, providerID string) (*OutgoingShare, error)
	GetOutgoingShareByWebDAVID(ctx context.Context, webdavID string) (*OutgoingShare, error)
	GetOutgoingShareBySharedSecret(ctx context.Context, sharedSecret string) (*OutgoingShare, error)
	UpdateOutgoingShare(ctx context.Context, share *OutgoingShare) error
	DeleteOutgoingShare(ctx context.Context, providerID string) error
	ListOutgoingShares(ctx context.Context) ([]*OutgoingShare, error)
}

// IncomingShareStore manages incoming share persistence (receiver-side).
// All mutating operations are scoped by recipientUserID to prevent cross-user access.
type IncomingShareStore interface {
	CreateIncomingShare(ctx context.Context, share *IncomingShare) error
	GetIncomingShareByIDForRecipient(ctx context.Context, shareID string, recipientUserID string) (*IncomingShare, error)
	GetIncomingShareByProviderKey(ctx context.Context, senderHost, providerID string) (*IncomingShare, error)
	ListIncomingSharesByRecipient(ctx context.Context, recipientUserID string) ([]*IncomingShare, error)
	UpdateIncomingShareStatusForRecipient(ctx context.Context, shareID string, recipientUserID string, status string) error
	DeleteIncomingShareForRecipient(ctx context.Context, shareID string, recipientUserID string) error
}

// OutgoingInviteStore manages outgoing invite persistence (initiator-side).
type OutgoingInviteStore interface {
	CreateOutgoingInvite(ctx context.Context, invite *OutgoingInvite) error
	GetOutgoingInvite(ctx context.Context, id string) (*OutgoingInvite, error)
	GetOutgoingInviteByToken(ctx context.Context, token string) (*OutgoingInvite, error)
	UpdateOutgoingInvite(ctx context.Context, invite *OutgoingInvite) error
	DeleteOutgoingInvite(ctx context.Context, id string) error
	ListOutgoingInvites(ctx context.Context, userID string) ([]*OutgoingInvite, error)
}

// IncomingInviteStore manages incoming invite persistence (acceptor-side).
// All mutating operations are scoped by recipientUserID to prevent cross-user access.
// Update is intentionally status-plus-sender-identity: scope-defining fields
// (Token, RecipientUserID) cannot be reassigned after creation.
type IncomingInviteStore interface {
	CreateIncomingInvite(ctx context.Context, invite *IncomingInvite) error
	GetIncomingInviteForRecipient(ctx context.Context, id string, recipientUserID string) (*IncomingInvite, error)
	GetIncomingInviteByToken(ctx context.Context, token string, recipientUserID string) (*IncomingInvite, error)
	UpdateIncomingInviteStatusForRecipient(ctx context.Context, id string, recipientUserID string, status string, senderUserID string, senderFQDNNormalized string) error
	DeleteIncomingInviteForRecipient(ctx context.Context, id string, recipientUserID string) error
	ListIncomingInvites(ctx context.Context, recipientUserID string) ([]*IncomingInvite, error)
}

// OutgoingShare represents a share created by this instance (sender-side).
type OutgoingShare struct {
	ShareID    string `gorm:"uniqueIndex" json:"shareId"`    // sender-local identity (UUIDv7)
	ProviderID string `gorm:"primaryKey"  json:"providerId"` // provider-assigned share id
	WebDAVID   string `gorm:"uniqueIndex" json:"webdavId"`
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
	Status           string   `gorm:"column:status"                                                    json:"status"` // sent, accepted, declined
	Error            string   `json:"error,omitempty"`
	Requirements     []string `gorm:"serializer:json"                                                  json:"requirements,omitempty"`
	CreatedAt        int64    `json:"createdAt"`
	UpdatedAt        int64    `json:"updatedAt"`
}

// IncomingShare represents a share received by this instance (receiver-side).
// The composite unique index on (senderHost, providerID) enforces that one
// provider-key pair can be stored at most once, matching GetIncomingShareByProviderKey
// singular semantics.
type IncomingShare struct {
	ShareID           string `gorm:"primaryKey"                                                      json:"shareId"`    // receiver-local id (UUIDv7)
	SenderHost        string `gorm:"column:sender_host;uniqueIndex:idx_incoming_shares_provider_key" json:"senderHost"` // sender's host
	ProviderID        string `gorm:"uniqueIndex:idx_incoming_shares_provider_key"                    json:"providerId"` // sender's share id
	WebDAVID          string `json:"webdavId,omitempty"`                                                                // relative or absolute webdav URI
	SharedSecret      string `json:"sharedSecret,omitempty"`                                                            // omitempty for redaction
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
	WebappTargets     []string `gorm:"serializer:json"                json:"webappTargets,omitempty"`
	ProtocolName      string   `json:"protocolName,omitempty"`
	Status            string   `gorm:"column:status"                  json:"status"` // pending, accepted, declined
	RecipientUserID   string   `gorm:"column:recipient_user_id;index" json:"recipientUserId"`
	OwnerHost         string   `json:"ownerHost"`
	Requirements      []string `gorm:"serializer:json"                json:"requirements,omitempty"`
	// Expiration is a Unix epoch; 0 means no expiration.
	Expiration int64 `json:"expiration,omitempty"`
	CreatedAt  int64 `json:"createdAt"`
	UpdatedAt  int64 `json:"updatedAt"`
}

// OutgoingInvite is the persistence model for outgoing invites (initiator-side).
type OutgoingInvite struct {
	ID              string `gorm:"primaryKey"               json:"id"`
	Token           string `gorm:"uniqueIndex"              json:"token"`
	ProviderFQDN    string `gorm:"column:provider_fqdn"     json:"providerFqdn"`
	InviteString    string `json:"inviteString"`
	RecipientEmail  string `json:"recipientEmail,omitempty"`
	CreatedByUserID string `gorm:"index"                    json:"createdByUserId"`
	Status          string `json:"status"` // pending, accepted
	// AcceptedProviderFQDN is the raw remote provider host from the
	// invite-accepted request. AcceptedUserID is the canonical remote accepter
	// user identity (userID). AcceptedProviderFQDNNormalized is the accepting
	// provider in host compare form; the latter two feed the must-invite gate.
	AcceptedProviderFQDN           string `gorm:"column:accepted_provider_fqdn"            json:"acceptedProviderFqdn,omitempty"`
	AcceptedUserID                 string `gorm:"column:accepted_user_id"                  json:"acceptedUserId,omitempty"`
	AcceptedProviderFQDNNormalized string `gorm:"column:accepted_provider_fqdn_normalized" json:"acceptedProviderFqdnNormalized,omitempty"`
	ExpiresAt                      int64  `json:"expiresAt"`
	CreatedAt                      int64  `json:"createdAt"`
	UpdatedAt                      int64  `json:"updatedAt"`
	AcceptedAt                     int64  `json:"acceptedAt,omitempty"` // unix epoch; 0 = not yet accepted
}

// IncomingInvite is the persistence model for incoming invites (acceptor-side).
// The composite unique index on (token, recipientUserID) enforces that one
// recipient can accept any given token at most once.
type IncomingInvite struct {
	ID              string `gorm:"primaryKey"                                       json:"id"`
	Token           string `gorm:"uniqueIndex:idx_incoming_invites_token_recipient" json:"token"`
	InviteString    string `json:"inviteString"`
	SenderFQDN      string `gorm:"column:sender_fqdn"                               json:"senderFqdn"`
	RecipientUserID string `gorm:"uniqueIndex:idx_incoming_invites_token_recipient" json:"recipientUserId"`
	Status          string `json:"status"` // pending, accepted
	// SenderUserID is the canonical remote sender user identity from the
	// invite-accepted response. SenderFQDNNormalized is the sender host in
	// compare form; both feed the must-invite gate.
	SenderUserID         string `json:"senderUserId,omitempty"`
	SenderFQDNNormalized string `gorm:"column:sender_fqdn_normalized" json:"senderFqdnNormalized,omitempty"`
	ReceivedAt           int64  `json:"receivedAt"`
	UpdatedAt            int64  `json:"updatedAt"`
}
