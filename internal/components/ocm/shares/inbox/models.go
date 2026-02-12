// Package inbox provides incoming share models and repository.
package inbox

import (
	"time"
)

type IncomingShare struct {
	ShareID   string `json:"shareId"`   // local UUIDv7
	ProviderID string `json:"providerId"`
	SenderHost string `json:"senderHost"`

	WebDAVID         string `json:"webdavId,omitempty"`
	WebDAVURIAbsolute string `json:"webdavUriAbsolute,omitempty"` // deprecated
	SharedSecret     string `json:"-"`

	Permissions []string `json:"permissions"`

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

	RecipientUserID      string `json:"-"`
	RecipientDisplayName string `json:"-"`

	Status    ShareStatus `json:"status"`
	CreatedAt time.Time   `json:"createdAt"`
	UpdatedAt time.Time   `json:"updatedAt"`
	MustExchangeToken bool `json:"mustExchangeToken,omitempty"`
}

type ShareStatus string

const (
	ShareStatusPending  ShareStatus = "pending"
	ShareStatusAccepted ShareStatus = "accepted"
	ShareStatusDeclined ShareStatus = "declined"
)
