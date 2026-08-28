// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

const (
	msgAbortNotReady = "session is not ready for abort"
	msgAbortMiss     = "abort did not match session state"
	msgAbortRefused  = "abort refused while the run can still pass"
)

type abortResponse struct {
	ID    string `json:"id"`
	State string `json:"state"`
}

// HandleAbort serves POST /api/session/{id}/abort. The URL id is the only
// session key. An active row is hard-failed through ReleaseActiveHardFail;
// a passive row stays on POST /stop.
func (h *Handler) HandleAbort(w http.ResponseWriter, r *http.Request) {
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

	ctx := r.Context()

	if h.respondAbortLookup(w, ctx, id) {
		return
	}

	if abortErr := h.store.ReleaseActiveHardFail(ctx, id, validatorcore.ReasonOperatorAborted); abortErr != nil {
		h.writeAbortError(w, abortErr)

		return
	}

	h.writeReloadedAbort(w, ctx, id)
}

// respondAbortLookup loads the row and writes the handler-owned unknown and
// inactive answers. The store still collapses those rows to one miss; this
// read is only for the HTTP split. It returns true when HandleAbort should
// stop.
func (h *Handler) respondAbortLookup(w http.ResponseWriter, ctx context.Context, id string) bool {
	row, err := h.store.GetTestRun(ctx, id)
	if err != nil {
		if errors.Is(err, validatorcore.ErrSessionNotFound) {
			writeJSONError(w, h.log, http.StatusNotFound, validatorcore.CodeSessionNotFound, "session not found")

			return true
		}

		writeStoreError(w, h.log, err)

		return true
	}

	if row.IsActive {
		return false
	}

	if validatorcore.IsTerminalState(row.State) {
		writeJSONError(w, h.log, http.StatusConflict, validatorcore.CodeAbortSessionMiss, msgAbortMiss)

		return true
	}

	writeJSONError(w, h.log, http.StatusConflict, validatorcore.CodeSessionNotReady, msgAbortNotReady)

	return true
}

func (h *Handler) writeReloadedAbort(w http.ResponseWriter, ctx context.Context, id string) {
	row, err := h.store.GetTestRun(ctx, id)
	if err != nil {
		writeStoreError(w, h.log, err)

		return
	}

	writeJSON(w, h.log, http.StatusOK, abortResponse{ID: id, State: row.State})
}

func (h *Handler) writeAbortError(w http.ResponseWriter, err error) {
	if errors.Is(err, validatorcore.ErrActiveHardFailRefused) {
		writeJSONError(w, h.log, http.StatusConflict, validatorcore.CodeAbortRefused, msgAbortRefused)

		return
	}

	if errors.Is(err, validatorcore.ErrStateTransitionMiss) {
		writeJSONError(w, h.log, http.StatusConflict, validatorcore.CodeAbortSessionMiss, msgAbortMiss)

		return
	}

	writeStoreError(w, h.log, err)
}
