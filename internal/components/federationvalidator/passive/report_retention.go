// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

type retentionPatchRequest struct {
	RetentionTier string `json:"retentionTier"`
}

type retentionWriteResponse struct {
	ID            string `json:"id"`
	RetentionTier string `json:"retentionTier"`
	Locked        bool   `json:"locked,omitempty"`
}

// HandleReportRetention serves PATCH /api/report/{id}/retention.
func (h *Handler) HandleReportRetention(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPatch {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)

		return
	}

	row, ok := h.loadPublicRetentionRow(w, r)
	if !ok {
		return
	}

	if !h.requireTerminalReport(w, row) {
		return
	}

	if row.RetentionLockedAt != nil {
		writeJSONError(w, h.log, http.StatusConflict, codeRetentionLocked, "retention is locked")

		return
	}

	body, err := readLimitedBody(w, h.log, r, maxStartBodyBytes)
	if err != nil {
		return
	}

	var req retentionPatchRequest
	if unmarshalErr := json.Unmarshal(body, &req); unmarshalErr != nil {
		writeJSONError(w, h.log, http.StatusBadRequest, "invalid_request", "invalid JSON body")

		return
	}

	tier := strings.TrimSpace(req.RetentionTier)

	write, writeOK := retentionWriteForTier(row.FinishedAt, tier, time.Now().Unix())
	if !writeOK {
		writeJSONError(w, h.log, http.StatusBadRequest, codeInvalidTier, "unknown retention tier")

		return
	}

	write.RetentionTier = &tier
	write.RequireUnlocked = true

	if h.afterRetentionPatchReady != nil {
		h.afterRetentionPatchReady()
	}

	if !h.updateReportRetention(w, r, row.TestRunID, write) {
		return
	}

	writeJSON(w, h.log, http.StatusOK, retentionWriteResponse{
		ID:            row.TestRunID,
		RetentionTier: tier,
	})
}

func (h *Handler) requireTerminalReport(w http.ResponseWriter, row *validatorcore.TestRun) bool {
	if row.FinishedAt != nil {
		return true
	}

	writeJSONError(w, h.log, http.StatusConflict, codeReportNotTerminal, "report is not terminal")

	return false
}

func (h *Handler) loadPublicRetentionRow(
	w http.ResponseWriter,
	r *http.Request,
) (*validatorcore.TestRun, bool) {
	if h.store == nil {
		writeJSONError(w, h.log, http.StatusInternalServerError, "store_unavailable", "validator store is not configured")

		return nil, false
	}

	id := strings.TrimSpace(chi.URLParam(r, "id"))
	if id == "" {
		writeJSONError(w, h.log, http.StatusNotFound, validatorcore.CodeSessionNotFound, "session not found")

		return nil, false
	}

	row, err := h.store.GetTestRun(r.Context(), id)
	if err != nil {
		if errors.Is(err, validatorcore.ErrSessionNotFound) {
			writeJSONError(w, h.log, http.StatusNotFound, validatorcore.CodeSessionNotFound, "session not found")

			return nil, false
		}

		writeStoreError(w, h.log, fmt.Errorf("load report: %w", err))

		return nil, false
	}

	if !validatorcore.PermanentOptedIn(row) {
		writeJSONError(w, h.log, http.StatusNotFound, codeReportNotPublic, "report is not public")

		return nil, false
	}

	if row.HarvestedAt != nil || validatorcore.ReportExpired(row, time.Now().Unix()) {
		writeJSONError(w, h.log, http.StatusGone, codeReportExpired, "report has expired")

		return nil, false
	}

	return row, true
}

func (h *Handler) updateReportRetention(
	w http.ResponseWriter,
	r *http.Request,
	id string,
	write validatorcore.ReportRetentionWrite,
) bool {
	if h.store == nil {
		writeJSONError(w, h.log, http.StatusInternalServerError, "store_unavailable", "validator store is not configured")

		return false
	}

	affected, err := h.store.UpdatePublicReportRetention(r.Context(), id, time.Now().Unix(), write)
	if err != nil {
		writeJSONError(w, h.log, http.StatusInternalServerError, "store_error", "failed to update retention")

		return false
	}

	if affected == 0 {
		h.writeRetentionUpdateMiss(w, r, id, write.RequireUnlocked)

		return false
	}

	return true
}

func (h *Handler) writeRetentionUpdateMiss(
	w http.ResponseWriter,
	r *http.Request,
	id string,
	requireUnlocked bool,
) {
	row, err := h.store.GetTestRun(r.Context(), id)
	if err != nil {
		if errors.Is(err, validatorcore.ErrSessionNotFound) {
			writeJSONError(w, h.log, http.StatusNotFound, validatorcore.CodeSessionNotFound, "session not found")

			return
		}

		writeStoreError(w, h.log, fmt.Errorf("load report: %w", err))

		return
	}

	if !validatorcore.PermanentOptedIn(row) {
		writeJSONError(w, h.log, http.StatusNotFound, codeReportNotPublic, "report is not public")

		return
	}

	if row.HarvestedAt != nil || validatorcore.ReportExpired(row, time.Now().Unix()) {
		writeJSONError(w, h.log, http.StatusGone, codeReportExpired, "report has expired")

		return
	}

	if requireUnlocked && row.RetentionLockedAt != nil {
		writeJSONError(w, h.log, http.StatusConflict, codeRetentionLocked, "retention is locked")

		return
	}

	writeJSONError(w, h.log, http.StatusNotFound, codeReportNotPublic, "report is not public")
}

func retentionWriteForTier(
	finishedAt *int64,
	tier string,
	updatedAt int64,
) (validatorcore.ReportRetentionWrite, bool) {
	expires, ok := reportExpiresAt(finishedAt, tier)
	if !ok {
		return validatorcore.ReportRetentionWrite{}, false
	}

	return validatorcore.ReportRetentionWrite{
		ExpiresAt:      expires,
		ClearExpiresAt: expires == nil,
		UpdatedAt:      updatedAt,
	}, true
}

func reportExpiresAt(finishedAt *int64, tier string) (*int64, bool) {
	days, forever, ok := validatorcore.RetentionTierDays(tier)
	if !ok {
		return nil, false
	}

	if finishedAt == nil || forever {
		return nil, true
	}

	expires := *finishedAt + int64(days)*validatorcore.SecondsPerDay

	return &expires, true
}
