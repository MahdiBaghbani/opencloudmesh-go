// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

// HandleReportLock serves POST /api/report/{id}/lock.
func (h *Handler) HandleReportLock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
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
		h.writeLockOK(w, row)

		return
	}

	if h.afterRetentionLockReady != nil {
		h.afterRetentionLockReady()
	}

	if !h.lockPublicReport(w, r, row.TestRunID) {
		return
	}

	current, err := h.store.GetTestRun(r.Context(), row.TestRunID)
	if err != nil {
		writeStoreError(w, h.log, fmt.Errorf("load report: %w", err))

		return
	}

	h.writeLockOK(w, current)
}

func (h *Handler) lockPublicReport(w http.ResponseWriter, r *http.Request, id string) bool {
	if h.store == nil {
		writeJSONError(w, h.log, http.StatusInternalServerError, "store_unavailable", "validator store is not configured")

		return false
	}

	affected, err := h.store.LockPublicReportRetention(r.Context(), id, time.Now().Unix())
	if err != nil {
		writeJSONError(w, h.log, http.StatusInternalServerError, "store_error", "failed to lock retention")

		return false
	}

	if affected == 0 {
		h.writeLockUpdateMiss(w, r, id)

		return false
	}

	return true
}

func (h *Handler) writeLockUpdateMiss(w http.ResponseWriter, r *http.Request, id string) {
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

	if row.RetentionLockedAt != nil {
		h.writeLockOK(w, row)

		return
	}

	writeJSONError(w, h.log, http.StatusNotFound, codeReportNotPublic, "report is not public")
}

func (h *Handler) writeLockOK(w http.ResponseWriter, row *validatorcore.TestRun) {
	tier := validatorcore.DefaultRetentionTier
	if row.RetentionTier != nil && *row.RetentionTier != "" {
		tier = *row.RetentionTier
	}

	writeJSON(w, h.log, http.StatusOK, retentionWriteResponse{
		ID:            row.TestRunID,
		RetentionTier: tier,
		Locked:        true,
	})
}
