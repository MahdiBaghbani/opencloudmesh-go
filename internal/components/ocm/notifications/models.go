// Package notifications implements OCM notification handling.
package notifications

import (
	"time"
)

// NotificationType represents the type of notification.
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

// NotificationRecord represents a stored notification.
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

// IsValidNotificationType checks if a notification type is valid.
func IsValidNotificationType(t NotificationType) bool {
	switch t {
	case NotificationShareAccepted, NotificationShareDeclined, NotificationShareUnshared:
		return true
	}
	return false
}
