// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

const (
	msgStopNotReady = "session is not ready for stop"
	msgStopMiss     = "stop did not match session state"
)

type stopRequest struct {
	ID string `json:"id"`
}

type stopResponse struct {
	ID    string `json:"id"`
	State string `json:"state"`
}

// HandleStop serves POST /stop for core-only terminalization from
// passive_complete. Dest is re-read before StopPassive. The response state
// is always reloaded from the store and is never hardcoded. An
// already-terminal row returns HTTP 200 and the persisted state.
func (h *Handler) HandleStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)

		return
	}

	if h.store == nil {
		writeJSONError(w, h.log, http.StatusInternalServerError, "store_unavailable", "validator store is not configured")

		return
	}

	id, ok := h.decodeStopID(w, r)
	if !ok {
		return
	}

	ctx := r.Context()

	if h.respondStopDest(w, ctx, id) {
		return
	}

	if stopErr := h.store.StopPassive(ctx, id); stopErr != nil {
		h.writeStopError(w, stopErr)

		return
	}

	h.writeReloadedStop(w, ctx, id)
}

func (h *Handler) decodeStopID(w http.ResponseWriter, r *http.Request) (string, bool) {
	body, err := readLimitedBody(w, h.log, r, maxStartBodyBytes)
	if err != nil {
		return "", false
	}

	var req stopRequest
	if unmarshalErr := json.Unmarshal(body, &req); unmarshalErr != nil {
		writeJSONError(w, h.log, http.StatusBadRequest, "invalid_request", "invalid JSON body")

		return "", false
	}

	id := strings.TrimSpace(req.ID)
	if id == "" {
		writeJSONError(w, h.log, http.StatusBadRequest, "invalid_request", "id is required")

		return "", false
	}

	return id, true
}

// respondStopDest loads dest and writes a terminal or not-ready response.
// It returns true when HandleStop should stop.
func (h *Handler) respondStopDest(w http.ResponseWriter, ctx context.Context, id string) bool {
	row, err := h.store.GetTestRun(ctx, id)
	if err != nil {
		writeStoreError(w, h.log, err)

		return true
	}

	if validatorcore.IsTerminalState(row.State) {
		writeJSON(w, h.log, http.StatusOK, stopResponse{ID: id, State: row.State})

		return true
	}

	if !canStopPassive(row) {
		writeJSONError(w, h.log, http.StatusConflict, validatorcore.CodeSessionNotReady, msgStopNotReady)

		return true
	}

	return false
}

func (h *Handler) writeReloadedStop(w http.ResponseWriter, ctx context.Context, id string) {
	row, err := h.store.GetTestRun(ctx, id)
	if err != nil {
		writeStoreError(w, h.log, err)

		return
	}

	writeJSON(w, h.log, http.StatusOK, stopResponse{ID: id, State: row.State})
}

func (h *Handler) writeStopError(w http.ResponseWriter, err error) {
	if errors.Is(err, validatorcore.ErrStateTransitionMiss) {
		writeJSONError(w, h.log, http.StatusConflict, validatorcore.CodeStopSessionMiss, msgStopMiss)

		return
	}

	writeStoreError(w, h.log, err)
}

func canStopPassive(row *validatorcore.TestRun) bool {
	if row == nil {
		return false
	}

	return !row.IsActive && row.State == validatorcore.StatePassiveComplete
}
