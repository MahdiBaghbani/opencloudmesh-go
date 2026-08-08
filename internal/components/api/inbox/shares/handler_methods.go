// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package shares

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/access"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/reason"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares"
	sharesincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/incoming"
)

// HandleList handles GET /api/inbox/shares; returns only shares for the authenticated user.
func (h *Handler) HandleList(w http.ResponseWriter, r *http.Request) {
	user, err := h.currentUser(r.Context())
	if err != nil {
		api.WriteUnauthorized(w, api.ReasonUnauthenticated, "authentication required")

		return
	}

	result, err := h.repo.ListByRecipientUserID(r.Context(), user.ID)
	if err != nil {
		h.log.Error("failed to list inbox shares", "user_id", user.ID, "error", err)
		api.WriteInternalError(w, "failed to list inbox shares")

		return
	}

	views := make([]InboxShareView, 0, len(result))
	for _, s := range result {
		views = append(views, NewInboxShareView(s))
	}

	w.Header().Set("Content-Type", "application/json")
	//nolint:errcheck,errchkjson // response already committed after WriteHeader; write error cannot be recovered or meaningfully handled; payload encodes to fixed JSON, so encode error is always nil
	json.NewEncoder(w).Encode(InboxListResponse{Shares: views})
}

// HandleAccept handles POST /api/inbox/shares/{shareId}/accept; idempotent if already accepted.
func (h *Handler) HandleAccept(w http.ResponseWriter, r *http.Request) {
	user, err := h.currentUser(r.Context())
	if err != nil {
		api.WriteUnauthorized(w, api.ReasonUnauthenticated, "authentication required")

		return
	}

	shareID := chi.URLParam(r, "shareId")
	if shareID == "" {
		api.WriteBadRequest(w, api.ReasonMissingField, "shareId is required")

		return
	}

	ctx := r.Context()

	share, err := h.repo.GetByIDForRecipientUserID(ctx, shareID, user.ID)
	if err != nil {
		if errors.Is(err, sharesincoming.ErrShareNotFound) {
			api.WriteNotFound(w, "share not found")

			return
		}

		h.log.Error("failed to get share", "share_id", shareID, "user_id", user.ID, "error", err)
		api.WriteInternalError(w, "failed to get share")

		return
	}

	if share.Status == shares.ShareStatusAccepted {
		w.Header().Set("Content-Type", "application/json")
		//nolint:errcheck,errchkjson // response already committed after WriteHeader; write error cannot be recovered or meaningfully handled; payload encodes to fixed JSON, so encode error is always nil
		json.NewEncoder(w).Encode(map[string]string{
			jsonKeyStatus:  string(shares.ShareStatusAccepted),
			jsonKeyShareID: shareID,
		})

		return
	}

	if share.Status == shares.ShareStatusDeclined {
		api.WriteConflict(w, "share has already been declined")

		return
	}

	if err := h.repo.UpdateStatusForRecipientUserID(ctx, shareID, user.ID, shares.ShareStatusAccepted); err != nil {
		h.log.Error("failed to update share status", "share_id", shareID, "error", err)
		api.WriteInternalError(w, "failed to update share status")

		return
	}

	w.Header().Set("Content-Type", "application/json")
	//nolint:errcheck,errchkjson // response already committed after WriteHeader; write error cannot be recovered or meaningfully handled; payload encodes to fixed JSON, so encode error is always nil
	json.NewEncoder(w).Encode(map[string]string{
		jsonKeyStatus:  string(shares.ShareStatusAccepted),
		jsonKeyShareID: shareID,
	})
}

// HandleGetDetail handles GET /api/inbox/shares/{shareId}; returns protocol info with secrets masked.
func (h *Handler) HandleGetDetail(w http.ResponseWriter, r *http.Request) {
	user, err := h.currentUser(r.Context())
	if err != nil {
		api.WriteUnauthorized(w, api.ReasonUnauthenticated, "authentication required")

		return
	}

	shareID := chi.URLParam(r, "shareId")
	if shareID == "" {
		api.WriteBadRequest(w, api.ReasonMissingField, "shareId is required")

		return
	}

	share, err := h.repo.GetByIDForRecipientUserID(r.Context(), shareID, user.ID)
	if err != nil {
		if errors.Is(err, sharesincoming.ErrShareNotFound) {
			api.WriteNotFound(w, "share not found")

			return
		}

		h.log.Error("failed to get share", "share_id", shareID, "user_id", user.ID, "error", err)
		api.WriteInternalError(w, "failed to get share")

		return
	}

	detail := NewInboxShareDetailView(share)

	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(detail); err != nil {
		h.log.Error("failed to encode share detail", "error", err)
	}
}

// HandleDecline handles POST /api/inbox/shares/{shareId}/decline.
func (h *Handler) HandleDecline(w http.ResponseWriter, r *http.Request) {
	user, err := h.currentUser(r.Context())
	if err != nil {
		api.WriteUnauthorized(w, api.ReasonUnauthenticated, "authentication required")

		return
	}

	shareID := chi.URLParam(r, "shareId")
	if shareID == "" {
		api.WriteBadRequest(w, api.ReasonMissingField, "shareId is required")

		return
	}

	ctx := r.Context()

	share, err := h.repo.GetByIDForRecipientUserID(ctx, shareID, user.ID)
	if err != nil {
		if errors.Is(err, sharesincoming.ErrShareNotFound) {
			api.WriteNotFound(w, "share not found")

			return
		}

		h.log.Error("failed to get share", "share_id", shareID, "user_id", user.ID, "error", err)
		api.WriteInternalError(w, "failed to get share")

		return
	}

	if share.Status == shares.ShareStatusDeclined {
		w.Header().Set("Content-Type", "application/json")

		if err := json.NewEncoder(w).Encode(map[string]string{
			jsonKeyStatus:  string(shares.ShareStatusDeclined),
			jsonKeyShareID: shareID,
		}); err != nil {
			h.log.Error("failed to encode declined share", "error", err)
		}

		return
	}

	if share.Status == shares.ShareStatusAccepted {
		api.WriteConflict(w, "share has already been accepted")

		return
	}

	if err := h.repo.UpdateStatusForRecipientUserID(ctx, shareID, user.ID, shares.ShareStatusDeclined); err != nil {
		h.log.Error("failed to update share status", "share_id", shareID, "error", err)
		api.WriteInternalError(w, "failed to update share status")

		return
	}

	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(map[string]string{
		jsonKeyStatus:  string(shares.ShareStatusDeclined),
		jsonKeyShareID: shareID,
	}); err != nil {
		h.log.Error("failed to encode declined share", "error", err)
	}
}

// HandleVerifyAccess handles POST /api/inbox/shares/{shareId}/verify-access; all access is server-side (no secrets to browser).
func (h *Handler) HandleVerifyAccess(w http.ResponseWriter, r *http.Request) {
	user, err := h.currentUser(r.Context())
	if err != nil {
		api.WriteUnauthorized(w, api.ReasonUnauthenticated, "authentication required")

		return
	}

	shareID := chi.URLParam(r, "shareId")
	if shareID == "" {
		api.WriteBadRequest(w, api.ReasonMissingField, "shareId is required")

		return
	}

	ctx := r.Context()

	share, err := h.repo.GetByIDForRecipientUserID(ctx, shareID, user.ID)
	if err != nil {
		if errors.Is(err, sharesincoming.ErrShareNotFound) {
			api.WriteNotFound(w, "share not found")

			return
		}

		h.log.Error("failed to get share", "share_id", shareID, "user_id", user.ID, "error", err)
		api.WriteInternalError(w, "failed to get share")

		return
	}

	if share.Status != shares.ShareStatusAccepted {
		writeVerifyError(w, http.StatusBadRequest, verifyReasonShareNotAccepted, "share must be accepted before verifying access")

		return
	}

	protocol := access.ProtocolWebDAV
	if share.WebappURI != "" || strings.EqualFold(share.ProtocolName, access.ProtocolWebapp) {
		protocol = access.ProtocolWebapp
	}

	shareInfo := access.ShareInfo{
		Status:            string(share.Status),
		SenderHost:        share.SenderHost,
		OwnerHost:         share.OwnerHost,
		SharedSecret:      share.SharedSecret,
		ProtocolName:      share.ProtocolName,
		Requirements:      share.Requirements,
		WebDAVID:          share.WebDAVID,
		WebappURI:         share.WebappURI,
		WebappTargets:     share.WebappTargets,
		WebappPermissions: share.WebappPermissions,
	}

	result, err := h.accessClient.Access(ctx, access.AccessOptions{
		Share:    &shareInfo,
		Protocol: protocol,
		Method:   "GET",
	})
	if err != nil {
		h.writeAccessError(w, err)

		return
	}
	defer func() {
		//nolint:errcheck // best-effort cleanup; error is not actionable
		result.Response.Body.Close()
	}()

	if result.Response.StatusCode < 200 || result.Response.StatusCode >= 300 {
		writeVerifyError(w, reason.APIStatus(reason.PeerUnreachable), reason.VerifyCode(reason.PeerUnreachable),
			"remote server returned "+redactPeerValue(result.Response.Status, share.SharedSecret))

		return
	}

	preview, truncated, readErr := readBoundedPreview(result.Response.Body)
	if readErr != nil {
		h.log.Warn("partial read of remote response body", "share_id", shareID, "error", readErr)
	}

	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(VerifyAccessResponse{
		OK:                      true,
		HTTPStatus:              result.Response.StatusCode,
		ContentType:             redactPeerValue(result.Response.Header.Get("Content-Type"), share.SharedSecret),
		ContentPreview:          redactPeerValue(string(preview), share.SharedSecret),
		ContentPreviewTruncated: truncated,
	}); err != nil {
		h.log.Error("failed to encode verify access response", "error", err)
	}
}

// readBoundedPreview reads up to maxPreviewBytes; truncation=true if more bytes exist.
func readBoundedPreview(r io.Reader) ([]byte, bool, error) {
	buf, err := io.ReadAll(io.LimitReader(r, int64(maxPreviewBytes+1)))
	if len(buf) > maxPreviewBytes {
		if err != nil {
			return buf[:maxPreviewBytes], true, fmt.Errorf("api: read bounded preview: %w", err)
		}

		return buf[:maxPreviewBytes], true, nil
	}

	if err != nil {
		return buf, false, fmt.Errorf("api: read bounded preview: %w", err)
	}

	return buf, false, nil
}

// redactPeerValue redacts peer-controlled values (preview, content-type,
// status text) before they reach the browser.
func redactPeerValue(value, secret string) string {
	const redacted = "[REDACTED]"
	if secret != "" {
		value = strings.ReplaceAll(value, secret, redacted)
	}

	value = strings.ReplaceAll(value, "code=", "[REDACTED_CODE_PARAM]")
	value = strings.ReplaceAll(value, "sharedSecret", "[REDACTED_FIELD]")

	return value
}

// writeVerifyError writes a VerifyAccessResponse with ok=false.
func writeVerifyError(w http.ResponseWriter, statusCode int, reasonCode, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	//nolint:errcheck,errchkjson // response already committed after WriteHeader; write error cannot be recovered or meaningfully handled; payload encodes to fixed JSON, so encode error is always nil
	json.NewEncoder(w).Encode(VerifyAccessResponse{
		OK:         false,
		ReasonCode: reasonCode,
		Error:      message,
	})
}

func (h *Handler) writeAccessError(w http.ResponseWriter, err error) {
	if errors.Is(err, access.ErrShareNotAccepted) {
		writeVerifyError(w, http.StatusBadRequest, verifyReasonShareNotAccepted, "share not accepted")

		return
	}

	if errors.Is(err, access.ErrTokenExchangeRequired) {
		writeVerifyError(w, reason.APIStatus(reason.PeerCapabilityMismatch), reason.VerifyCode(reason.PeerCapabilityMismatch), "token exchange required but not available")

		return
	}

	if errors.Is(err, access.ErrRemoteAccessFailed) {
		writeVerifyError(w, reason.APIStatus(reason.PeerUnreachable), reason.VerifyCode(reason.PeerUnreachable), "remote access failed: all methods exhausted")

		return
	}

	reasonCode := reason.CanonicalFromError(err)
	writeVerifyError(w, reason.APIStatus(reasonCode), reason.VerifyCode(reasonCode), "remote access failed")
}
