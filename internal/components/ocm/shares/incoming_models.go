// Package shares implements OCM share creation and inbox handling.
package shares

import (
	"time"
)

// NewShareRequest represents an incoming POST /ocm/shares request body.
// See OCM-API spec v1.2.2 NewShare schema.
type NewShareRequest struct {
	ShareWith         string   `json:"shareWith"`
	Name              string   `json:"name"`
	Description       string   `json:"description,omitempty"`
	ProviderID        string   `json:"providerId"`
	Owner             string   `json:"owner"`
	Sender            string   `json:"sender"`
	OwnerDisplayName  string   `json:"ownerDisplayName,omitempty"`
	SenderDisplayName string   `json:"senderDisplayName,omitempty"`
	ShareType         string   `json:"shareType"`
	ResourceType      string   `json:"resourceType"`
	Expiration        *int64   `json:"expiration,omitempty"`
	Protocol          Protocol `json:"protocol"`
}

// Protocol contains protocol-specific options.
type Protocol struct {
	Name   string          `json:"name,omitempty"`
	WebDAV *WebDAVProtocol `json:"webdav,omitempty"`
	WebApp *WebAppProtocol `json:"webapp,omitempty"`
}

// WebDAVProtocol contains WebDAV access options.
type WebDAVProtocol struct {
	AccessTypes  []string `json:"accessTypes,omitempty"`
	URI          string   `json:"uri"`
	SharedSecret string   `json:"sharedSecret,omitempty"`
	Permissions  []string `json:"permissions"`
	Requirements []string `json:"requirements,omitempty"`
}

// RequirementMustExchangeToken is the requirement indicating token exchange is required.
const RequirementMustExchangeToken = "must-exchange-token"

// HasRequirement checks if the protocol has a specific requirement.
func (p *WebDAVProtocol) HasRequirement(req string) bool {
	for _, r := range p.Requirements {
		if r == req {
			return true
		}
	}
	return false
}

// WebAppProtocol contains webapp access options.
type WebAppProtocol struct {
	URI          string `json:"uri"`
	SharedSecret string `json:"sharedSecret,omitempty"`
	ViewMode     string `json:"viewMode,omitempty"`
}

// CreateShareResponse is the spec-aligned 201/200 response for POST /ocm/shares.
// Only includes spec-required fields; do not serialize the full IncomingShare.
type CreateShareResponse struct {
	RecipientDisplayName string `json:"recipientDisplayName"`
}

// IncomingShare represents a stored incoming share in the inbox.
type IncomingShare struct {
	// ShareID is the local inbox record ID (UUIDv7)
	ShareID string `json:"shareId"`

	// ProviderID is the opaque share ID from the sender
	ProviderID string `json:"providerId"`

	// SenderHost is the normalized host of the sender (for scoped storage)
	SenderHost string `json:"senderHost"`

	// WebDAVID is the relative WebDAV identifier (from webdav.uri)
	WebDAVID string `json:"webdavId,omitempty"`

	// WebDAVURIAbsolute is set if webdav.uri was an absolute URI (deprecated)
	WebDAVURIAbsolute string `json:"webdavUriAbsolute,omitempty"`

	// SharedSecret for WebDAV access (never logged or returned in listings)
	SharedSecret string `json:"-"`

	// Permissions from webdav.permissions
	Permissions []string `json:"permissions"`

	// Metadata
	Owner             string `json:"owner"`
	Sender            string `json:"sender"`
	ShareWith         string `json:"shareWith"`
	Name              string `json:"name"`
	Description       string `json:"description,omitempty"`
	ResourceType      string `json:"resourceType"`
	ShareType         string `json:"shareType"`
	OwnerDisplayName  string `json:"ownerDisplayName,omitempty"`
	SenderDisplayName string `json:"senderDisplayName,omitempty"`
	Expiration        *int64 `json:"expiration,omitempty"`

	// Recipient identity (set at ingest time from resolved local user)
	RecipientUserID     string `json:"-"` // canonical local user id that owns this inbox entry
	RecipientDisplayName string `json:"-"` // resolved display name for 201 response

	// State
	Status    ShareStatus `json:"status"`
	CreatedAt time.Time   `json:"createdAt"`
	UpdatedAt time.Time   `json:"updatedAt"`

	// Token exchange
	MustExchangeToken bool `json:"mustExchangeToken,omitempty"`
}

// ShareStatus represents the acceptance state of an incoming share.
type ShareStatus string

const (
	ShareStatusPending  ShareStatus = "pending"
	ShareStatusAccepted ShareStatus = "accepted"
	ShareStatusDeclined ShareStatus = "declined"
)

// InboxShareView is the safe view of an IncomingShare for API responses.
// It explicitly excludes sensitive fields like SharedSecret.
type InboxShareView struct {
	ShareID           string      `json:"shareId"`
	ProviderID        string      `json:"providerId"`
	Name              string      `json:"name"`
	Description       string      `json:"description,omitempty"`
	Owner             string      `json:"owner"`
	Sender            string      `json:"sender"`
	SenderHost        string      `json:"senderHost"`
	ShareWith         string      `json:"shareWith"`
	ResourceType      string      `json:"resourceType"`
	ShareType         string      `json:"shareType"`
	Permissions       []string    `json:"permissions"`
	Status            ShareStatus `json:"status"`
	CreatedAt         time.Time   `json:"createdAt"`
	OwnerDisplayName  string      `json:"ownerDisplayName,omitempty"`
	SenderDisplayName string      `json:"senderDisplayName,omitempty"`
}

// ToView converts an IncomingShare to a safe view for API responses.
func (s *IncomingShare) ToView() InboxShareView {
	return InboxShareView{
		ShareID:           s.ShareID,
		ProviderID:        s.ProviderID,
		Name:              s.Name,
		Description:       s.Description,
		Owner:             s.Owner,
		Sender:            s.Sender,
		SenderHost:        s.SenderHost,
		ShareWith:         s.ShareWith,
		ResourceType:      s.ResourceType,
		ShareType:         s.ShareType,
		Permissions:       s.Permissions,
		Status:            s.Status,
		CreatedAt:         s.CreatedAt,
		OwnerDisplayName:  s.OwnerDisplayName,
		SenderDisplayName: s.SenderDisplayName,
	}
}
