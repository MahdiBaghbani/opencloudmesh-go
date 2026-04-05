// Package notifications implements OCM notification handling.
// See https://github.com/cs3org/OCM-API/blob/a2b8bacd4590ff201a06883330b67636e99c4f5b/IETF-RFC.md?plain=1#share-acceptance-notification
package notifications

import (
	"time"
)

type NotificationType string

const (
	NotificationShareAccepted NotificationType = "SHARE_ACCEPTED"
	NotificationShareDeclined NotificationType = "SHARE_DECLINED"
	NotificationShareUnshared NotificationType = "SHARE_UNSHARED"
)

// NewNotification represents an incoming POST /ocm/notifications request.
// See OCM-API spec v1.2.2 NewNotification schema.
type NewNotification struct {
	NotificationType       NotificationType `json:"notificationType"`
	ResourceType           string           `json:"resourceType"`
	ProviderID             string           `json:"providerId"`
	Notification           interface{}      `json:"notification,omitempty"`
	SendingServiceOwnerURL string           `json:"sendingServiceOwnerURL,omitempty"`
}

type NotificationRecord struct {
	ID                string           `json:"id"`
	NotificationType  NotificationType `json:"notificationType"`
	ResourceType      string           `json:"resourceType"`
	ProviderID        string           `json:"providerId"`
	SenderHost        string           `json:"senderHost"`
	Notification      interface{}      `json:"notification,omitempty"`
	ReceivedAt        time.Time        `json:"receivedAt"`
	Processed         bool             `json:"processed"`
}

func IsValidNotificationType(t NotificationType) bool {
	switch t {
	case NotificationShareAccepted, NotificationShareDeclined, NotificationShareUnshared:
		return true
	}
	return false
}
