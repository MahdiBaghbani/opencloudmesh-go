// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package incoming

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"

	inboundsignature "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/inbound/signature"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares"
	sharesincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/incoming"
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/hostport"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
)

const (
	ocmErrSenderNotAuthorized = "SENDER_NOT_AUTHORIZED"
	ocmErrShareStatusConflict = "SHARE_STATUS_CONFLICT"
)

// Handler serves POST /ocm/notifications for inbound share lifecycle updates.
type Handler struct {
	outgoingRepo sharesoutgoing.OutgoingShareRepo
	incomingRepo sharesincoming.IncomingShareRepo
	localScheme  string
	log          *slog.Logger
}

// NewHandler creates the notifications handler.
func NewHandler(
	outgoingRepo sharesoutgoing.OutgoingShareRepo,
	incomingRepo sharesincoming.IncomingShareRepo,
	localScheme string,
	log *slog.Logger,
) *Handler {
	return &Handler{
		outgoingRepo: outgoingRepo,
		incomingRepo: incomingRepo,
		localScheme:  localScheme,
		log:          logutil.NoopIfNil(log),
	}
}

// HandleNotification handles POST /ocm/notifications.
func (h *Handler) HandleNotification(w http.ResponseWriter, r *http.Request) {
	req, ok := h.parseNotificationRequest(w, r)
	if !ok {
		return
	}

	senderHost, ok := h.authenticatedSenderHost(w, r)
	if !ok {
		return
	}

	switch req.NotificationType {
	case spec.NotificationTypeShareAccepted:
		h.updateOutgoingShareStatus(w, r.Context(), senderHost, &req, shares.OutgoingShareStatusAccepted, "outgoing share accepted via notification")
	case spec.NotificationTypeShareDeclined:
		h.updateOutgoingShareStatus(w, r.Context(), senderHost, &req, shares.OutgoingShareStatusDeclined, "outgoing share declined via notification")
	case spec.NotificationTypeShareUnshared:
		h.handleShareUnshared(w, r.Context(), senderHost, &req)
	default:
		h.log.Warn("unsupported notification type", "notification_type", req.NotificationType)
		spec.WriteOCMError(w, http.StatusBadRequest, "INVALID_NOTIFICATION_REQUEST")
	}
}

func (h *Handler) parseNotificationRequest(w http.ResponseWriter, r *http.Request) (spec.NotificationRequest, bool) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.log.Warn("failed to read notification request body", "error", err)
		spec.WriteOCMError(w, http.StatusBadRequest, "INVALID_JSON")

		return spec.NotificationRequest{}, false
	}

	var req spec.NotificationRequest
	if err := json.Unmarshal(body, &req); err != nil {
		h.log.Warn("failed to decode notification request", "error", err)
		spec.WriteOCMError(w, http.StatusBadRequest, "INVALID_JSON")

		return spec.NotificationRequest{}, false
	}

	if validationErrs := spec.ValidateNotificationRequest(&req); len(validationErrs) > 0 {
		h.log.Warn("notification validation failed", "errors", len(validationErrs))
		spec.WriteValidationError(w, "INVALID_NOTIFICATION_REQUEST", validationErrs)

		return spec.NotificationRequest{}, false
	}

	return req, true
}

func (h *Handler) authenticatedSenderHost(w http.ResponseWriter, r *http.Request) (string, bool) {
	peerIdentity := inboundsignature.GetPeerIdentity(r.Context())
	if peerIdentity == nil || !peerIdentity.Authenticated || peerIdentity.AuthorityForCompare == "" {
		h.log.Warn("notification request missing authenticated peer identity")
		spec.WriteOCMError(w, http.StatusForbidden, "UNTRUSTED_PROVIDER")

		return "", false
	}

	return peerIdentity.AuthorityForCompare, true
}

func (h *Handler) updateOutgoingShareStatus(
	w http.ResponseWriter,
	ctx context.Context,
	senderHost string,
	req *spec.NotificationRequest,
	wantStatus shares.OutgoingShareStatus,
	successLog string,
) {
	share, err := h.outgoingRepo.GetByProviderID(ctx, req.ProviderID)
	if err != nil {
		if errors.Is(err, sharesoutgoing.ErrShareNotFound) {
			spec.WriteOCMError(w, http.StatusNotFound, "SHARE_NOT_FOUND")

			return
		}

		h.log.Error("failed to load outgoing share for notification", "provider_id", req.ProviderID, "error", err)
		spec.WriteOCMError(w, http.StatusInternalServerError, "INTERNAL_ERROR")

		return
	}

	if !h.senderMatchesHost(senderHost, share.ReceiverHost) {
		h.log.Warn("notification sender not authorized for outgoing share",
			"provider_id", req.ProviderID,
			"sender_host", senderHost,
			"receiver_host", share.ReceiverHost)
		spec.WriteOCMError(w, http.StatusForbidden, ocmErrSenderNotAuthorized)

		return
	}

	if share.Status == wantStatus {
		writeNotificationSuccess(w)

		return
	}

	if isOppositeOutgoingTerminalStatus(share.Status, wantStatus) {
		h.log.Warn("notification conflicts with outgoing share terminal status",
			"provider_id", req.ProviderID,
			"current_status", share.Status,
			"notification_status", wantStatus)
		spec.WriteOCMError(w, http.StatusConflict, ocmErrShareStatusConflict)

		return
	}

	share.Status = wantStatus
	if err := h.outgoingRepo.Update(ctx, share); err != nil {
		h.log.Error("failed to update outgoing share status", "provider_id", req.ProviderID, "error", err)
		spec.WriteOCMError(w, http.StatusInternalServerError, "INTERNAL_ERROR")

		return
	}

	h.log.Info(successLog, "provider_id", req.ProviderID)
	writeNotificationSuccess(w)
}

func (h *Handler) handleShareUnshared(
	w http.ResponseWriter,
	ctx context.Context,
	senderHost string,
	req *spec.NotificationRequest,
) {
	share, err := h.incomingRepo.GetByProviderID(ctx, senderHost, req.ProviderID)
	if err != nil {
		if errors.Is(err, sharesincoming.ErrShareNotFound) {
			spec.WriteOCMError(w, http.StatusNotFound, "SHARE_NOT_FOUND")

			return
		}

		h.log.Error("failed to load incoming share for notification",
			"provider_id", req.ProviderID,
			"sender_host", senderHost,
			"error", err)
		spec.WriteOCMError(w, http.StatusInternalServerError, "INTERNAL_ERROR")

		return
	}

	if !h.senderMatchesHost(senderHost, share.SenderHost) {
		h.log.Warn("notification sender host mismatch for incoming share",
			"provider_id", req.ProviderID,
			"sender_host", senderHost,
			"stored_sender_host", share.SenderHost)
		spec.WriteOCMError(w, http.StatusForbidden, ocmErrSenderNotAuthorized)

		return
	}

	if share.Status == shares.ShareStatusUnshared {
		writeNotificationSuccess(w)

		return
	}

	if err := h.incomingRepo.UpdateStatusForRecipientUserID(
		ctx,
		share.ShareID,
		share.RecipientUserID,
		shares.ShareStatusUnshared,
	); err != nil {
		h.log.Error("failed to update incoming share status",
			"provider_id", req.ProviderID,
			"sender_host", senderHost,
			"error", err)
		spec.WriteOCMError(w, http.StatusInternalServerError, "INTERNAL_ERROR")

		return
	}

	h.log.Info("incoming share unshared via notification",
		"provider_id", req.ProviderID,
		"sender_host", senderHost)
	writeNotificationSuccess(w)
}

func (h *Handler) senderMatchesHost(senderHost, storedHost string) bool {
	normalizedStored, err := hostport.Normalize(storedHost, h.localScheme)
	if err != nil {
		return false
	}

	normalizedSender, err := hostport.Normalize(senderHost, h.localScheme)
	if err != nil {
		return false
	}

	return normalizedSender == normalizedStored
}

func isOppositeOutgoingTerminalStatus(current, want shares.OutgoingShareStatus) bool {
	if current == shares.OutgoingShareStatusAccepted {
		return want == shares.OutgoingShareStatusDeclined
	}

	if current == shares.OutgoingShareStatusDeclined {
		return want == shares.OutgoingShareStatusAccepted
	}

	return false
}

func writeNotificationSuccess(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	//nolint:errcheck,errchkjson // response already committed after WriteHeader; write error cannot be recovered or meaningfully handled; payload encodes to fixed JSON, so encode error is always nil
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
