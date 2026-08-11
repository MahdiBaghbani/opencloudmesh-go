// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package spec

import "encoding/json"

const (
	// NotificationTypeShareAccepted is sent when a receiver accepts a share.
	NotificationTypeShareAccepted = "SHARE_ACCEPTED"
	// NotificationTypeShareDeclined is sent when a receiver declines a share.
	NotificationTypeShareDeclined = "SHARE_DECLINED"
	// NotificationTypeShareUnshared is sent when the sender revokes a share.
	NotificationTypeShareUnshared = "SHARE_UNSHARED"

	// Experimental notification types rejected by ocmgo.
	notificationTypeRequestReshare          = "REQUEST_RESHARE"
	notificationTypeReshareUndo             = "RESHARE_UNDO"
	notificationTypeReshareChangePermission = "RESHARE_CHANGE_PERMISSION"

	fieldNotificationType = "notificationType"
	fieldProviderID       = "providerId"
)

// SupportedNotificationTypes lists the core notification types implemented by ocmgo.
var SupportedNotificationTypes = []string{
	NotificationTypeShareAccepted,
	NotificationTypeShareDeclined,
	NotificationTypeShareUnshared,
}

var supportedNotificationTypes = map[string]struct{}{
	NotificationTypeShareAccepted: {},
	NotificationTypeShareDeclined: {},
	NotificationTypeShareUnshared: {},
}

var experimentalNotificationTypes = map[string]struct{}{
	notificationTypeRequestReshare:          {},
	notificationTypeReshareUndo:             {},
	notificationTypeReshareChangePermission: {},
}

// NotificationRequest carries the wire body for POST /ocm/notifications.
// See https://github.com/cs3org/OCM-API/blob/6a0586183cbef10ecae9dedc42561806447eb2f5/IETF-OCM.md
type NotificationRequest struct {
	NotificationType string          `json:"notificationType"`
	ProviderID       string          `json:"providerId"`
	ResourceType     string          `json:"resourceType,omitempty"`
	Notification     json.RawMessage `json:"notification,omitempty"`
}

// ValidateNotificationRequest returns validation errors for a notification request.
func ValidateNotificationRequest(req *NotificationRequest) []ValidationError {
	var errs []ValidationError

	if req.NotificationType == "" {
		errs = append(errs, ValidationError{
			Name:    fieldNotificationType,
			Message: validationRequired,
		})
	}

	if req.ProviderID == "" {
		errs = append(errs, ValidationError{
			Name:    fieldProviderID,
			Message: validationRequired,
		})
	}

	if req.NotificationType == "" {
		return errs
	}

	if _, experimental := experimentalNotificationTypes[req.NotificationType]; experimental {
		errs = append(errs, ValidationError{
			Name:    fieldNotificationType,
			Message: validationUnsupported,
		})

		return errs
	}

	if _, ok := supportedNotificationTypes[req.NotificationType]; !ok {
		errs = append(errs, ValidationError{
			Name:    fieldNotificationType,
			Message: validationUnsupported,
		})
	}

	return errs
}
