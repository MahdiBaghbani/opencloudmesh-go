// Package outgoing provides outgoing share models and repository.
package outgoing

import (
	"time"
)

// OutgoingShare holds a share created locally for a remote receiver.
type OutgoingShare struct {
	ShareID          string `json:"shareId"`
	ProviderID       string `json:"providerId"`
	WebDAVID         string `json:"webdavId"`
	SharedSecret     string `json:"-"`
	LocalPath        string `json:"localPath"`
	ReceiverHost     string `json:"receiverHost"`
	ReceiverEndPoint string `json:"receiverEndPoint"`
	ShareWith        string `json:"shareWith"`

	Name         string     `json:"name"`
	ResourceType string     `json:"resourceType"`
	ShareType    string     `json:"shareType"`
	Permissions  []string   `json:"permissions"`
	Owner        string     `json:"owner"`
	Sender       string     `json:"sender"`
	Status       string     `json:"status"`
	CreatedAt    time.Time  `json:"createdAt"`
	SentAt       *time.Time `json:"sentAt,omitempty"`
	Error        string     `json:"error,omitempty"`
	Requirements []string   `json:"requirements,omitempty"`
}

// OutgoingShareRequest carries the body for creating an outgoing share.
type OutgoingShareRequest struct {
	ReceiverDomain string   `json:"receiverDomain"`
	ShareWith      string   `json:"shareWith"`
	LocalPath      string   `json:"localPath"`
	Name           string   `json:"name,omitempty"`
	Permissions    []string `json:"permissions"`
	ResourceType   string   `json:"resourceType,omitempty"`
}
