// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

const maxStartBodyBytes = 4096

// Handler serves plane-A passive validator session endpoints.
type Handler struct {
	store *validatorcore.Core
	probe *ProbeRunner
	log   *slog.Logger
}

// NewHandler returns a passive validator HTTP handler.
func NewHandler(store *validatorcore.Core, log *slog.Logger) *Handler {
	return NewHandlerWithDiscovery(store, nil, log)
}

// NewHandlerWithDiscovery returns a passive handler with optional discovery fetch wiring.
func NewHandlerWithDiscovery(
	store *validatorcore.Core,
	discoveryClient DiscoveryFetcher,
	log *slog.Logger,
) *Handler {
	log = logutil.NoopIfNil(log)

	return &Handler{
		store: store,
		probe: NewProbeRunnerWithDiscovery(store, discoveryClient, log),
		log:   log,
	}
}

type startCreateResponse struct {
	ID             string `json:"id"`
	OptInStats     bool   `json:"optInStats"`
	OptInPermanent bool   `json:"optInPermanent"`
}

type startExtendResponse struct {
	ID    string `json:"id"`
	State string `json:"state"`
}

type stopRequest struct {
	ID string `json:"id"`
}

type stopResponse struct {
	ID    string `json:"id"`
	State string `json:"state"`
}

type sessionPollResponse struct {
	State string `json:"state"`
	Ts    int64  `json:"ts"`
}

// HandleStart serves POST /start for passive-core create and active extension.
func (h *Handler) HandleStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)

		return
	}

	if h.store == nil {
		writeJSONError(w, h.log, http.StatusInternalServerError, "store_unavailable", "validator store is not configured")

		return
	}

	body, err := readLimitedBody(w, h.log, r, maxStartBodyBytes)
	if err != nil {
		return
	}

	req, decodeErr := decodeStartRequest(body)
	if decodeErr != nil {
		writeJSONError(w, h.log, http.StatusBadRequest, "invalid_request", "invalid JSON body")

		return
	}

	hasTarget := strings.TrimSpace(req.Target) != ""
	hasID := strings.TrimSpace(req.ID) != ""

	if hasTarget && hasID {
		writeJSONError(w, h.log, http.StatusBadRequest, "invalid_request", "request body must be target or id, not both")

		return
	}

	if hasID && optInKeysPresent(req) {
		writeJSONError(
			w,
			h.log,
			http.StatusBadRequest,
			codeOptInCreateOnly,
			"opt-in fields are write-once at create",
		)

		return
	}

	switch {
	case hasTarget:
		h.handleCreateSession(
			w,
			r,
			strings.TrimSpace(req.Target),
			startConsent(req, validatorcore.OptInChannelStart),
		)
	case hasID:
		h.handleExtendSession(w, r, strings.TrimSpace(req.ID))
	default:
		writeJSONError(w, h.log, http.StatusBadRequest, "invalid_request", "request body requires target or id")
	}
}

// HandleStop serves POST /stop for core-only terminalization from passive_complete.
func (h *Handler) HandleStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)

		return
	}

	if h.store == nil {
		writeJSONError(w, h.log, http.StatusInternalServerError, "store_unavailable", "validator store is not configured")

		return
	}

	body, err := readLimitedBody(w, h.log, r, maxStartBodyBytes)
	if err != nil {
		return
	}

	var req stopRequest
	if unmarshalErr := json.Unmarshal(body, &req); unmarshalErr != nil {
		writeJSONError(w, h.log, http.StatusBadRequest, "invalid_request", "invalid JSON body")

		return
	}

	id := strings.TrimSpace(req.ID)
	if id == "" {
		writeJSONError(w, h.log, http.StatusBadRequest, "invalid_request", "id is required")

		return
	}

	ctx := r.Context()

	row, err := h.store.GetTestRun(ctx, id)
	if err != nil {
		writeStoreError(w, h.log, err)

		return
	}

	if row.State != validatorcore.StatePassiveComplete {
		writeJSONError(
			w,
			h.log,
			http.StatusConflict,
			validatorcore.CodeSessionNotReady,
			"session is not ready for stop",
		)

		return
	}

	if row.IsActive {
		writeJSONError(
			w,
			h.log,
			http.StatusConflict,
			validatorcore.CodeSessionNotReady,
			"session is not ready for stop",
		)

		return
	}

	if err := h.store.StopPassiveComplete(ctx, id); err != nil {
		if errors.Is(err, validatorcore.ErrStateTransitionMiss) {
			writeJSONError(w, h.log, http.StatusConflict, validatorcore.CodeStopSessionMiss, "stop did not match session state")

			return
		}

		writeStoreError(w, h.log, err)

		return
	}

	writeJSON(w, h.log, http.StatusOK, stopResponse{ID: id, State: validatorcore.StateTerminalPass})
}

// HandleScan serves GET /api/scan for passive-core session creation with optional
// statistics contribute opt-in via the contribute query parameter and optional
// permanent report opt-in via the permanent query parameter.
func (h *Handler) HandleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)

		return
	}

	if h.store == nil {
		writeJSONError(w, h.log, http.StatusInternalServerError, "store_unavailable", "validator store is not configured")

		return
	}

	target := strings.TrimSpace(r.URL.Query().Get("target"))
	if target == "" {
		writeJSONError(w, h.log, http.StatusBadRequest, "invalid_request", "target query parameter is required")

		return
	}

	opt := sessionOptIn{
		Stats:     ParseContribute(r.URL.Query().Get("contribute")),
		Permanent: ParsePermanent(r.URL.Query().Get("permanent")),
		Channel:   validatorcore.OptInChannelScan,
	}
	h.handleCreateSession(w, r, target, opt)
}

// HandleSession serves GET /api/session/{id} for anonymous session polling.
func (h *Handler) HandleSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
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

	row, err := h.store.GetTestRun(r.Context(), id)
	if err != nil {
		if errors.Is(err, validatorcore.ErrSessionNotFound) {
			writeJSONError(w, h.log, http.StatusNotFound, validatorcore.CodeSessionNotFound, "session not found")

			return
		}

		writeStoreError(w, h.log, err)

		return
	}

	writeJSON(w, h.log, http.StatusOK, sessionPollResponse{
		State: row.State,
		Ts:    row.UpdatedAt,
	})
}

func (h *Handler) handleCreateSession(
	w http.ResponseWriter,
	r *http.Request,
	target string,
	opt sessionOptIn,
) {
	origin, host, err := parseTarget(target)
	if err != nil {
		writeJSONError(w, h.log, http.StatusBadRequest, "invalid_request", err.Error())

		return
	}

	testRunID, err := identity.UUIDv7()
	if err != nil {
		writeJSONError(w, h.log, http.StatusInternalServerError, "id_generation_failed", "failed to mint session id")

		return
	}

	now := time.Now().Unix()
	row := &validatorcore.TestRun{
		TestRunID:    testRunID,
		IsActive:     false,
		State:        validatorcore.StateCreated,
		TargetOrigin: origin,
		TargetHost:   host,
		DiscoveryURL: strings.TrimSuffix(origin, "/") + "/.well-known/ocm",
		SessionKind:  validatorcore.SessionKindPassiveOnly,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	applyCreateConsent(row, opt, now)

	ctx := r.Context()

	if err := h.store.CreatePassiveSession(ctx, row); err != nil {
		writeStoreError(w, h.log, err)

		return
	}

	h.probe.StartAsync(context.WithoutCancel(ctx), testRunID)

	writeJSON(w, h.log, http.StatusCreated, startCreateResponse{
		ID:             testRunID,
		OptInStats:     opt.Stats,
		OptInPermanent: opt.Permanent,
	})
}

func (h *Handler) handleExtendSession(w http.ResponseWriter, r *http.Request, testRunID string) {
	ctx := r.Context()

	if err := h.store.ExtendToActive(ctx, testRunID); err != nil {
		writeStoreError(w, h.log, err)

		return
	}

	writeJSON(w, h.log, http.StatusOK, startExtendResponse{
		ID:    testRunID,
		State: validatorcore.StateActiveRunning,
	})
}

func parseTarget(raw string) (origin, host string, err error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", "", errors.New("target must be an absolute URL with scheme and host")
	}

	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return "", "", errors.New("target scheme must be http or https")
	}

	origin = parsed.Scheme + "://" + parsed.Host
	host = strings.ToLower(parsed.Hostname())

	if host == "" {
		return "", "", errors.New("target must include a host")
	}

	return origin, host, nil
}

func readLimitedBody(w http.ResponseWriter, log *slog.Logger, r *http.Request, limit int64) ([]byte, error) {
	r.Body = http.MaxBytesReader(w, r.Body, limit)

	body, err := io.ReadAll(r.Body)
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			writeJSONError(w, log, http.StatusRequestEntityTooLarge, "payload_too_large", "request body too large")

			return nil, fmt.Errorf("read request body: %w", err)
		}

		writeJSONError(w, log, http.StatusBadRequest, "invalid_request", "invalid request body")

		return nil, fmt.Errorf("read request body: %w", err)
	}

	return body, nil
}

func writeStoreError(w http.ResponseWriter, log *slog.Logger, err error) {
	var storeErr *validatorcore.StoreError
	if errors.As(err, &storeErr) {
		switch storeErr.Op {
		case validatorcore.OpCreateSessionInsert:
			writeJSONError(w, log, http.StatusInternalServerError, "session_create_failed", "failed to create session")
		case validatorcore.OpExtendUpdate:
			writeJSONError(
				w,
				log,
				http.StatusConflict,
				validatorcore.CodeInteractiveRunInProgress,
				"interactive run in progress",
			)
		default:
			writeJSONError(w, log, http.StatusInternalServerError, "store_error", "validator store error")
		}

		return
	}

	switch {
	case errors.Is(err, validatorcore.ErrInFlightPassiveLimit):
		writeJSONError(
			w,
			log,
			http.StatusConflict,
			validatorcore.CodeInFlightPassiveLimit,
			"passive in-flight session limit reached",
		)
	case errors.Is(err, validatorcore.ErrSessionNotReady):
		writeJSONError(w, log, http.StatusConflict, validatorcore.CodeSessionNotReady, "session is not ready")
	case errors.Is(err, validatorcore.ErrInteractiveRunInProgress):
		writeJSONError(
			w,
			log,
			http.StatusConflict,
			validatorcore.CodeInteractiveRunInProgress,
			"interactive run in progress",
		)
	case errors.Is(err, validatorcore.ErrSessionNotFound):
		writeJSONError(w, log, http.StatusConflict, validatorcore.CodeSessionNotFound, "session not found")
	case errors.Is(err, validatorcore.ErrStopSessionMiss):
		writeJSONError(w, log, http.StatusConflict, validatorcore.CodeStopSessionMiss, "stop did not match session state")
	default:
		writeJSONError(w, log, http.StatusInternalServerError, "store_error", "validator store error")
	}
}

func writeJSON(w http.ResponseWriter, log *slog.Logger, status int, payload any) {
	log = logutil.NoopIfNil(log)

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(payload); err != nil {
		log.Warn("failed to encode JSON response", "error", err)

		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if _, err := w.Write(buf.Bytes()); err != nil {
		log.Warn("failed to write JSON response", "error", err)
	}
}

func writeJSONError(w http.ResponseWriter, log *slog.Logger, status int, code, message string) {
	writeJSON(w, log, status, map[string]string{
		"error":   code,
		"message": message,
	})
}
