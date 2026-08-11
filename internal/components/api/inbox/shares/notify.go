// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package shares

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/notifications"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
)

const notifyTimeout = 30 * time.Second

func (h *Handler) notifyShareStatusAsync(
	r *http.Request,
	senderHost, providerID, resourceType, notificationType string,
) {
	if h.notifier == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), notifyTimeout)
	notifier := h.notifier
	log := h.log

	go func() {
		defer cancel()

		err := notifier.Notify(ctx, senderHost, providerID, resourceType, notificationType, nil)
		if errors.Is(err, notifications.ErrNotificationsNotAdvertised) {
			return
		}

		if err != nil {
			log.Warn("failed to send share notification",
				"notification_type", notificationType,
				"provider_id", providerID,
				"sender_host", senderHost,
				"error", err)
		}
	}()
}

func (h *Handler) notifyShareAcceptedAsync(r *http.Request, senderHost, providerID, resourceType string) {
	h.notifyShareStatusAsync(r, senderHost, providerID, resourceType, spec.NotificationTypeShareAccepted)
}

func (h *Handler) notifyShareDeclinedAsync(r *http.Request, senderHost, providerID, resourceType string) {
	h.notifyShareStatusAsync(r, senderHost, providerID, resourceType, spec.NotificationTypeShareDeclined)
}
