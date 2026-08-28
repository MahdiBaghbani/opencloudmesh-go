// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

type claimInviteResponse struct {
	InviteString      string    `json:"inviteString"`
	IssuerFQDN        string    `json:"issuerFqdn"`
	PasteTargetOrigin string    `json:"pasteTargetOrigin"`
	PasteTargetHost   string    `json:"pasteTargetHost"`
	ExpiresAt         time.Time `json:"expiresAt"`
}

// HandleClaimInvite serves POST /api/session/{id}/invite. The first
// successful claim returns the invite string once; later claims return
// 410 without the token. The session is loaded by the URL id only.
func (h *Handler) HandleClaimInvite(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)

		return
	}

	if h.store == nil {
		writeJSONError(w, h.log, http.StatusInternalServerError, "store_unavailable", "validator store is not configured")

		return
	}

	id := strings.TrimSpace(chi.URLParam(r, "id"))
	if id == "" {
		writeJSONError(w, h.log, http.StatusNotFound, validatorcore.CodeSessionNotFound, "session not found")

		return
	}

	claimed, err := h.store.ClaimOutgoingInvite(r.Context(), id)
	if err != nil {
		writeClaimError(w, h, err)

		return
	}

	writeJSON(w, h.log, http.StatusOK, claimInviteResponse{
		InviteString:      claimed.InviteString,
		IssuerFQDN:        claimed.IssuerFQDN,
		PasteTargetOrigin: claimed.PasteTargetOrigin,
		PasteTargetHost:   claimed.PasteTargetHost,
		ExpiresAt:         claimed.ExpiresAt,
	})
}

func writeClaimError(w http.ResponseWriter, h *Handler, err error) {
	switch {
	case errors.Is(err, validatorcore.ErrInviteAlreadyClaimed):
		writeJSONError(
			w,
			h.log,
			http.StatusGone,
			validatorcore.CodeInviteAlreadyClaimed,
			"invite already claimed",
		)
	case errors.Is(err, validatorcore.ErrSessionNotFound):
		writeJSONError(w, h.log, http.StatusNotFound, validatorcore.CodeSessionNotFound, "session not found")
	case errors.Is(err, validatorcore.ErrSessionNotReady):
		writeJSONError(w, h.log, http.StatusConflict, validatorcore.CodeSessionNotReady, "session is not ready")
	default:
		h.log.Warn("validator claim failed")
		writeJSONError(w, h.log, http.StatusInternalServerError, "store_error", "validator store error")
	}
}
